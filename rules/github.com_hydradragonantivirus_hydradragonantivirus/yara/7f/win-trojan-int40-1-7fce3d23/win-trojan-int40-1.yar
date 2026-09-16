rule Win_Trojan_Int40_1
{
strings:
	$a0 = { 8ed0bc007cfc8ed88ec0bf00028bf48bdcb95c0251b90001f3a5c348b142d3e8743460be0001803e4f00c07228 }


condition:
	$a0
}