rule Win_Trojan_Emv_1
{
strings:
	$a0 = { 01010055df04000000ffff00000000cb020000050000000103 }


condition:
	$a0
}