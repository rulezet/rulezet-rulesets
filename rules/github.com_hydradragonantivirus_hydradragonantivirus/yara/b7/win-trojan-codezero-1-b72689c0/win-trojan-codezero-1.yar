rule Win_Trojan_CodeZero_1
{
strings:
	$a0 = { 8d9fe4020e07cd2107c3faf4cf30467bb947b40eac }


condition:
	$a0
}