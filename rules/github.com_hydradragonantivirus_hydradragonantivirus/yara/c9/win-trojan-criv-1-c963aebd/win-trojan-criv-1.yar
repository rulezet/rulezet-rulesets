rule Win_Trojan_Criv_1
{
strings:
	$a0 = { 83c404bfc45040008db42464040000b90900000033d2f3a67463 }


condition:
	$a0
}