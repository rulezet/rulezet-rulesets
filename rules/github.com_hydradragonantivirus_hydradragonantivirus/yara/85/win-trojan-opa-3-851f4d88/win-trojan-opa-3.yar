rule Win_Trojan_Opa_3
{
strings:
	$a0 = { 35cd21891e03018c060501b82125ba1001cd21ba6400b80031cd21 }


condition:
	$a0
}