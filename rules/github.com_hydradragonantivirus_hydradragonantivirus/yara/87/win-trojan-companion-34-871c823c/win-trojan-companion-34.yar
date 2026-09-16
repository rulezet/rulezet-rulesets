rule Win_Trojan_Companion_34
{
strings:
	$a0 = { b82135cd21891e????8c06????b82125ba????cd21eb28bb0d02d1ebd1ebd1 }


condition:
	$a0
}