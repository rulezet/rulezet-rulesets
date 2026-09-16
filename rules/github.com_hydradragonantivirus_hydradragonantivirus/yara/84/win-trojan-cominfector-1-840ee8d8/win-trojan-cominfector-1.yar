rule Win_Trojan_ComInfector_1
{
strings:
	$a0 = { b44e[0-8]cd21[0-200]b8023d[0-8]cd21[0-200]b440[0-8]cd21 }

	$a1 = { 2a2e434f4d00 }


condition:
	$a0 and $a1
}