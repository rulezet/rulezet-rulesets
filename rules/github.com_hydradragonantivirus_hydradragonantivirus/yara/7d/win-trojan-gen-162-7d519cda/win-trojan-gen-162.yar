rule Win_Trojan_Gen_162
{
strings:
	$a0 = { 8b3e7628c6856427438b3e7828c68564274f8b3e7a28c68564274de8d0febfe41a1e57bf64271e57 }


condition:
	$a0
}