rule Win_Trojan_Voodoo_4
{
strings:
	$a0 = { 0d7532e4428ae8e442243f8ac8e442241f8af0e442b403b280cd13b405b256cd21b24fcd21b2 }


condition:
	$a0
}