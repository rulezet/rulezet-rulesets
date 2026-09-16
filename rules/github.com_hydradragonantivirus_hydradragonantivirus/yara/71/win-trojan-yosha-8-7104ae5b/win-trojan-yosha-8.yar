rule Win_Trojan_Yosha_8
{
strings:
	$a0 = { b82135cd21891e????8c06????b82125ba????cd21585bcd21585bcd210e1f8e062c0033ff33c0ae75fd }


condition:
	$a0
}