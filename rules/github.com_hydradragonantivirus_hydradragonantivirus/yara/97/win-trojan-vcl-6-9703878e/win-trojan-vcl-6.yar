rule Win_Trojan_Vcl_6
{
strings:
	$a0 = { b8addecd2181fbadde7502[1-240]bf0001be????a5a4e9 }


condition:
	$a0
}