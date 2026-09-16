rule Win_Trojan_Nik_2
{
strings:
	$a0 = { 034e494b06b4facd2180fcfa75788cc1498ec1268b1e0300ba2202c1ea0483c2048cc12bda418ec1b44acd21 }


condition:
	$a0
}