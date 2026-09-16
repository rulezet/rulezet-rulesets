rule Win_Trojan_Euro1992_1
{
strings:
	$a0 = { 4bcd21720a83c62dbf000157a5a5 }


condition:
	$a0
}