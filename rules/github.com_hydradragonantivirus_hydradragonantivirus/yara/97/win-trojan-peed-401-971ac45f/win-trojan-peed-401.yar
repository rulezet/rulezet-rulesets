rule Win_Trojan_Peed_401
{
strings:
	$a0 = { 6a00e9ae000000bf0098a8e1bbf9ffffff01c789f89683c30783c40283c402b8 }


condition:
	$a0
}