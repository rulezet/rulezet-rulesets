rule Win_Trojan_Mirage_3
{
strings:
	$a0 = { 754b5f5f3c037415bf00015751be3306b9ccf9f3a4 }


condition:
	$a0
}