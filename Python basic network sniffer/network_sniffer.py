from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP

# Function to analyze Ethernet frames
def process_packet(packet):
    if packet.haslayer(Ether):
        ether_layer = packet.getlayer(Ether)
        print(f"\nEthernet Frame: Source MAC: {ether_layer.src}, Destination MAC: {ether_layer.dst}")

        # Check if it has an IP layer
        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            print(f"IPv4 Packet: Source IP: {ip_layer.src}, Destination IP: {ip_layer.dst}, Protocol: {ip_layer.proto}")

            # Check if it's a TCP packet
            if packet.haslayer(TCP):
                tcp_layer = packet.getlayer(TCP)
                print(f"TCP Segment: Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}")

                # HTTP data (assuming it's port 80 traffic)
                if tcp_layer.dport == 80 or tcp_layer.sport == 80:
                    print(f"HTTP Data: {bytes(packet[TCP].payload)}")
            
            # Check if it's a UDP packet
            elif packet.haslayer(UDP):
                udp_layer = packet.getlayer(UDP)
                print(f"UDP Segment: Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}")

            # Check if it's an ICMP packet
            elif packet.haslayer(ICMP):
                icmp_layer = packet.getlayer(ICMP)
                print(f"ICMP Packet: Type: {icmp_layer.type}, Code: {icmp_layer.code}")

# Start sniffing the network
def main():
    # Capture packets from all network interfaces (on Windows, Scapy automatically handles interface selection)
    print("Starting packet capture...")
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    main()
