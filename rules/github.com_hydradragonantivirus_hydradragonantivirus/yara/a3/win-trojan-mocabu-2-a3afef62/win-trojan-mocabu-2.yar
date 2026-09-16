rule Win_Trojan_Mocabu_2
{
strings:
	$a0 = { 8b451048753b8d45fcb9402c41008b15dc494100e806002f4c8b4dfcba4c2c4100b8602c4100e806011840eb148b5514 }


condition:
	$a0
}