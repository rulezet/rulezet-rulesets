rule Win_Trojan_Supra_3
{
strings:
	$a0 = { b82135cd21891e????8c06????b425ba????cd21[1-3]cd2780fc4b }


condition:
	$a0
}