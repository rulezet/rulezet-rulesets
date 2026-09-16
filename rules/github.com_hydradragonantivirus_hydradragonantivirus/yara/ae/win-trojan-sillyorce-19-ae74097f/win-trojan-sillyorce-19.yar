rule Win_Trojan_SillyORCE_19
{
strings:
	$a0 = { b82135cd21891e????8c06????b82125ba????cd21ba7d00cd27 }


condition:
	$a0
}