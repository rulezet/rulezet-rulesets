rule Win_Trojan_Tori_1
{
strings:
	$a0 = { 03cbb82135cd21891e27038c062903a1 }


condition:
	$a0
}