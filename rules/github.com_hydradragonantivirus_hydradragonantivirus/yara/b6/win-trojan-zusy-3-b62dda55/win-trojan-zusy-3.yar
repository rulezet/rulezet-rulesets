rule Win_Trojan_Zusy_3
{
strings:
	$a0 = { 8b35d8a0400050ffd6688cb7400053a368764100ffd750ffd66878b7400053a36c764100ffd750ffd6685cb74000 }


condition:
	$a0
}