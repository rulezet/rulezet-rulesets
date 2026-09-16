rule Win_Trojan_Froll_1
{
strings:
	$a0 = { d7bf8b07e863008bcf29d1b440cd2153e887008adae8820000d3b4008ac35b8bc8b4408bd0cd21 }


condition:
	$a0
}