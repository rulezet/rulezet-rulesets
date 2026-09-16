rule Win_Trojan_Selectron_3
{
strings:
	$a0 = { b82135cd21891e????8c06????b425ba????cd21c3b90002f7f1923d0000740142c3 }


condition:
	$a0
}