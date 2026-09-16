rule Win_Trojan_Joshi_5
{
strings:
	$a0 = { c181c300021e0e1f508ac12a06347c2c08581f72dccb }


condition:
	$a0
}