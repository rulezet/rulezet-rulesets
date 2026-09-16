rule Win_Trojan_Gidra_3
{
strings:
	$a0 = { ba8000b901008d9c7e03cd132680bc500551750b26c684500500b80103cd13c3b8014332ed }


condition:
	$a0
}