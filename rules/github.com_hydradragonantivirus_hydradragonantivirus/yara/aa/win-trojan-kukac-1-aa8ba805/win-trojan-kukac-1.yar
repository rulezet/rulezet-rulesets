rule Win_Trojan_Kukac_1
{
strings:
	$a0 = { 03bac10281ea000103f28b1c8b4c }


condition:
	$a0
}