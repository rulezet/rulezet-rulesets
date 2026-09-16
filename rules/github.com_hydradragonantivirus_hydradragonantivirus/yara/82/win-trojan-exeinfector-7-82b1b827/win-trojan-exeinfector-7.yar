rule Win_Trojan_ExeInfector_7
{
strings:
	$a0 = { 2a2e65786500 }

	$a1 = { b44e[0-8]cd21[0-200]b8023d[0-8]cd21[0-200]b440[0-8]cd21 }


condition:
	$a0 and $a1
}