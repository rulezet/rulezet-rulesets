rule Win_Trojan_BlackMonday_3
{
strings:
	$a0 = { 35cd21891eb7018c06b901baab01b8 }


condition:
	$a0
}