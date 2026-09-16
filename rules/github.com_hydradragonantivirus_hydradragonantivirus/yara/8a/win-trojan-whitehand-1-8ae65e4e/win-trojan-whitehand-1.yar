rule Win_Trojan_WhiteHand_1
{
strings:
	$a0 = { 54557303e9e800c6063407e983e803a33507050301a34f01eb48bf2207be4807a5a5a14207a3 }


condition:
	$a0
}