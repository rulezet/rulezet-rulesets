rule Win_Trojan_Fich_1
{
strings:
	$a0 = { 0135cd218c060201891e0401b80335 }


condition:
	$a0
}