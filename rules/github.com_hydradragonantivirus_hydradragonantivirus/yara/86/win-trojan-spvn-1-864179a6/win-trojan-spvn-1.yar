rule Win_Trojan_SPVN_1
{
strings:
	$a0 = { 01bfd3060e57bf0a0c1e57b81400509a6c0b2901c606530000b00050bf88031e57b8800050 }


condition:
	$a0
}