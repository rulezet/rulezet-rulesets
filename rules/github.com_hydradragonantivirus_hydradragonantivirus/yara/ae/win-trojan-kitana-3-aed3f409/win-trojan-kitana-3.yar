rule Win_Trojan_Kitana_3
{
strings:
	$a0 = { d2741e48cd13050101ba80008ac88bd8cd13803f857409fec441cd1387f3e2fac387de2eff0e13 }


condition:
	$a0
}