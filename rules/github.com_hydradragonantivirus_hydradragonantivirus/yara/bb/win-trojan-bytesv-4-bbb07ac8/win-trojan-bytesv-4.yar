rule Win_Trojan_ByteSV_4
{
strings:
	$a0 = { 5d83ed070e1f8d864100508a4621b9cb028d7641300446e2fbc3 }


condition:
	$a0
}