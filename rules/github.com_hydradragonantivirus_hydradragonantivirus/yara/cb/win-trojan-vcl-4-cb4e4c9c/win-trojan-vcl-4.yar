rule Win_Trojan_Vcl_4
{
strings:
	$a0 = { e800005d81ed????e99001[1-40]b8addecd2181fbadde7503eb }


condition:
	$a0
}