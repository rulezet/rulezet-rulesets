rule Win_Trojan_Hunter_2
{
strings:
	$a0 = { 01030055e0010001000200090300009a000000030000000903 }


condition:
	$a0
}