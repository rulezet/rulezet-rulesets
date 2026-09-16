rule Win_Trojan_Peed_224
{
strings:
	$a0 = { b826250300732fff125c40ffe35589e551418b7d0c66abc1c80290c1c80e66ab83 }


condition:
	$a0
}