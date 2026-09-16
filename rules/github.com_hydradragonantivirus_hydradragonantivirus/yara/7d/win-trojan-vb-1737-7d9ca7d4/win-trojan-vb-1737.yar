rule Win_Trojan_VB_1737
{
strings:
	$a0 = { 8c0000000000000100000000000000000041726765 }


condition:
	$a0
}