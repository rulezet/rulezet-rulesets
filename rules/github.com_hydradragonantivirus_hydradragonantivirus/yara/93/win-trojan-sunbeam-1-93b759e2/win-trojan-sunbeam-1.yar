rule Win_Trojan_Sunbeam_1
{
strings:
	$a0 = { 010300550001000000ffff00000000e1000000080000004f0c }


condition:
	$a0
}