rule Win_Trojan_VB_1068
{
strings:
	$a0 = { 6808124000e8f0ffffff00000000000030000000400000000000000006c2fed2 }


condition:
	$a0
}