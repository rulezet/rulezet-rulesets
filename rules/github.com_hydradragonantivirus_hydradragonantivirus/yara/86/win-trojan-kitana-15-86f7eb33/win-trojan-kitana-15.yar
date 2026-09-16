rule Win_Trojan_Kitana_15
{
strings:
	$a0 = { 8ac88bd8cd13803f85740ec740fd55aa418d00cd1387f3e2f8c387f30e1fff0e1304cd12c1 }


condition:
	$a0
}