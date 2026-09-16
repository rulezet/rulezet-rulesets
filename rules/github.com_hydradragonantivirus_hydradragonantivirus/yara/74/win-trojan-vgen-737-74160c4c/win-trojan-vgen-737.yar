rule Win_Trojan_VGEN_737
{
strings:
	$a0 = { c9ba2801cd2150ba6d01b94802bd0001e89f025bb440cd21b43ecd21b409ba3201cd21cd2068656c6c6f2e636f }


condition:
	$a0
}