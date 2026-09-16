rule Win_Trojan_Bancos_1778
{
strings:
	$a0 = { 820fbdbf8f7585f38fe4a8ab3156cd73dd9b7d7a5c7f92bb401310d6fd8e713cd90726eac7ba5d6d421a656b8866fcf8ef64e8b933885f68153ed0acc55a3af94ac204dd9742 }


condition:
	$a0
}