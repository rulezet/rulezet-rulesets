rule Win_Trojan_Kitana_13
{
strings:
	$a0 = { 13803f85740ec740fd55aa418d00cd1387f3e2f8c387f3970e1fff0e1304cd12c1e0068ec0b184 }


condition:
	$a0
}