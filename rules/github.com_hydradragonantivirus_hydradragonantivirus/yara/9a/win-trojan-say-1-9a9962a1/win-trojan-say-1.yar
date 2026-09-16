rule Win_Trojan_Say_1
{
strings:
	$a0 = { b82135cd21891e????8c06????b425ba????cd21c6062a0201e85e0116580306f702a3 }


condition:
	$a0
}