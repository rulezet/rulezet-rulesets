rule Win_Trojan_Chromo_1
{
strings:
	$a0 = { 3fb91a008d963802ccb43ecc3e81be38024d5a75b03e81be4a024d4c74a7 }


condition:
	$a0
}