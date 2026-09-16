rule Win_Trojan_Morid_1
{
strings:
	$a0 = { b800??????50c3 }

	$a1 = { 83c04866813858587501c3 }


condition:
	$a0 and $a1
}