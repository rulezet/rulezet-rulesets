rule Win_Trojan_Alma_1
{
strings:
	$a0 = { e8000000005b6805104000582bd8535d8dbd21104000b92a91000080375b47e2fa }


condition:
	$a0
}