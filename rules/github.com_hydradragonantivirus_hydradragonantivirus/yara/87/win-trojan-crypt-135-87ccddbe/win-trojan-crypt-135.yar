rule Win_Trojan_Crypt_135
{
strings:
	$a0 = { 6800??????58[0-50]8b4c2404[0-230]8d4c24f4[0-20]2eff29 }


condition:
	$a0
}