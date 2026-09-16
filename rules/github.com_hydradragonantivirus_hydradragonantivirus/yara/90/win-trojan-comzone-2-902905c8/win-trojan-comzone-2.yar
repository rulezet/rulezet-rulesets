rule Win_Trojan_Comzone_2
{
strings:
	$a0 = { b82135cd21891e????8c06????b425ba????cd21b44abb34000e07cd218c0e36 }


condition:
	$a0
}