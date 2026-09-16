rule Win_Trojan_Formater_1
{
strings:
	$a0 = { 050055000200000001006c080000e1020000030000006c08 }


condition:
	$a0
}