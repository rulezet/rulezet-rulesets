rule Win_Trojan_Peed_310
{
strings:
	$a0 = { e84a00000051b95802000089d781c190010000ab50525183 }


condition:
	$a0
}