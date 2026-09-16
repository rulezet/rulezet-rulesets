rule Win_Trojan_VGEN_316
{
strings:
	$a0 = { fcbe270181c7f200b90900f3a48a45ff2c4f8845ffbe3001b954008bfe2eff2625010001ad35ffffabe2f9eb76 }


condition:
	$a0
}