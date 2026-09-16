rule Win_Trojan_Riot_5
{
strings:
	$a0 = { e800008b2e0001bcfeff81ed1706be2a0603f5c604c3c604c6e8ccffe9d0fae9 }


condition:
	$a0
}