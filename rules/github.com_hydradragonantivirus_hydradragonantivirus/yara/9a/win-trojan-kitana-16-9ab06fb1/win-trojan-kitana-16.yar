rule Win_Trojan_Kitana_16
{
strings:
	$a0 = { 13803f85740ec740fd55aa418d00cd1387f3e2f8c387f333ff0e1fff0e1304cd12c1e0068ec0b1 }


condition:
	$a0
}