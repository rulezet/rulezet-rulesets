rule Win_Trojan_Gen_50
{
strings:
	$a0 = { bf0001be400603f72e8b8d0f00cd218c }


condition:
	$a0
}