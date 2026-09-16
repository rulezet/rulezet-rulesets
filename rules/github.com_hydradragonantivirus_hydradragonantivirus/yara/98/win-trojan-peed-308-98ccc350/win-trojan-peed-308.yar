rule Win_Trojan_Peed_308
{
strings:
	$a0 = { b96e090100baffbbbffff7d289d652ad05??????00eb03e2f6c351b95802000089d781c1b8240000ab50525183c8ff40 }


condition:
	$a0
}