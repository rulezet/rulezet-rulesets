rule Win_Trojan_Kriz_3
{
strings:
	$a0 = { 3636360000e00b000004000019a40c0003000100000004 }


condition:
	$a0
}