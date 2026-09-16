rule Win_Trojan_Duwende_14
{
strings:
	$a0 = { b82135cd21891e????8c06????b425ba????cd21071f5ec3cd20 }


condition:
	$a0
}