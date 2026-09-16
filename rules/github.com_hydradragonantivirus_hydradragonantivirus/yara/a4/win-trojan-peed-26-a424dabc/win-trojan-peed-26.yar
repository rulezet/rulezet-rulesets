rule Win_Trojan_Peed_26
{
strings:
	$a0 = { a4c8566e3b6d8835c83050e8dbf50d7e }


condition:
	$a0
}