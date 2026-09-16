rule Win_Trojan_Blurp_1
{
strings:
	$a0 = { 4d1243fe064f1250b440b97d12ba0000cd21582d0300a35912e87204b440b90500ba5812cd21 }


condition:
	$a0
}