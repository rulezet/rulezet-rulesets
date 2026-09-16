rule Win_Trojan_Tally34846_1
{
strings:
	$a0 = { 14c6381fd4b98bb440e95a720400ecece8e23dc350d8aeff58c3c2b4ff8a1780faf9cf0176d2f3 }


condition:
	$a0
}