rule Win_Trojan_Peed_307
{
strings:
	$a0 = { e84800000051b95802000089d781c1b8240000ab50525183c8ff4005d88c4000 }


condition:
	$a0
}