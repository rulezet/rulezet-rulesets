rule Win_Trojan_Morid_6
{
strings:
	$a0 = { b900??????51c3 }

	$a1 = { 83c14866813958587501c3 }


condition:
	$a0 and $a1
}