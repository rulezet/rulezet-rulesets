rule Win_Trojan_Arcv_11
{
strings:
	$a0 = { e80000582d110196e8 }

	$a1 = { 8dbc????b99d028035??47e2fac3 }


condition:
	$a0 and $a1
}