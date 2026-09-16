rule Win_Trojan_N_111
{
strings:
	$a0 = { e800005bbe0e0003f3b9f402301c46e2 }


condition:
	$a0
}