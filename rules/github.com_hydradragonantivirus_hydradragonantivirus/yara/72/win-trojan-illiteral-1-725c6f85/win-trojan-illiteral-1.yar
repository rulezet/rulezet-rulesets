rule Win_Trojan_Illiteral_1
{
strings:
	$a0 = { 01030055df00000100ffff0103000090030000040000000103 }


condition:
	$a0
}