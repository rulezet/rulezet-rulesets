rule Win_Trojan_Grog_13
{
strings:
	$a0 = { 3dcd219333ed33c933d2b80242cd2183fa007403e9b6 }


condition:
	$a0
}