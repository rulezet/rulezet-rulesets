rule Win_Trojan_Euskara_1
{
strings:
	$a0 = { 4526803d457510fcf3a48cc08ed8b425b009ba00facd21 }


condition:
	$a0
}