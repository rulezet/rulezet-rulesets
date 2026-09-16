rule Win_Trojan_Morid_3
{
strings:
	$a0 = { bb00??????53c3 }

	$a1 = { 83c34866813b58587501c3 }


condition:
	$a0 and $a1
}