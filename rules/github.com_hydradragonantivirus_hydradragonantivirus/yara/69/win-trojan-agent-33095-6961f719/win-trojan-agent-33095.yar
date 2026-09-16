rule Win_Trojan_Agent_33095
{
strings:
	$a0 = { 89968d68dae4e445f2a78826a537b1de2b4d5633d3ea0f212cec00fcbbbce4c1ac5b99e3d045550da8dcc27d3b53db043a35bd0c3d4cf3d782423280c49b86f23e75a199684f }


condition:
	$a0
}