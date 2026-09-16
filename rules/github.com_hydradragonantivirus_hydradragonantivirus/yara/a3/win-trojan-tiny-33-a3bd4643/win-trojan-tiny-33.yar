rule Win_Trojan_Tiny_33
{
strings:
	$a0 = { b97c00b440cd2192e8c3ffc7044de9897c02b440cd21b43e }


condition:
	$a0
}