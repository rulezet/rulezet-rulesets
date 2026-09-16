rule Win_Trojan_Soubor_1
{
strings:
	$a0 = { 6a005589e531c09acd026a00bf22021e57bfd2020e5731c0509a01076a009add056a009a91026a00bf22021e57 }


condition:
	$a0
}