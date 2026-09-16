rule Win_Trojan_Darkend_1
{
strings:
	$a0 = { 0e1eb800e9cd213d34127403e82100585b5a3bc37405b8 }


condition:
	$a0
}