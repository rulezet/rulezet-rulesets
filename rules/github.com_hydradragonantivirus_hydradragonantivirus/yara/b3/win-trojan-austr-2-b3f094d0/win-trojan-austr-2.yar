rule Win_Trojan_Austr_2
{
strings:
	$a0 = { 33c9cd218bd8b440b9bc028d968b01cd21b43ecd21c3 }


condition:
	$a0
}