rule Win_Trojan_Agent_35420
{
strings:
	$a0 = { 558bec6aff68702046006898df410064a10000000050648925 }

	$a1 = { 5057505353ff1548f142 }


condition:
	$a0 and $a1
}