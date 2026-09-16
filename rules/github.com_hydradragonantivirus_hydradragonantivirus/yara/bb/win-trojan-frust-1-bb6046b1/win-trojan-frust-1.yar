rule Win_Trojan_Frust_1
{
strings:
	$a0 = { e0009a00007a0089e5c606060200e800fce82afdb00050bf00011e57b8ff00509a060be000bf20031e57bf0001 }


condition:
	$a0
}