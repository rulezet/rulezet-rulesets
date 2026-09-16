rule Win_Trojan_Sofacy_1
{
strings:
	$a0 = { 8b45??8bca83f1??83e1??d3e830043a8b45??69c061ea0000357128142442 }


condition:
	$a0
}