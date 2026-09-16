rule Win_Trojan_Peed_335
{
strings:
	$a0 = { e83300000052ad05????????eb03e2f6c351b95802000089d781c190010000e825 }


condition:
	$a0
}