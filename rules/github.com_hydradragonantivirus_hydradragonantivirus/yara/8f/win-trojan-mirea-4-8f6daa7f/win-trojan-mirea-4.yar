rule Win_Trojan_Mirea_4
{
strings:
	$a0 = { c689d4fd980985c6fd930985ccfd8e0985dffe91719189fe }


condition:
	$a0
}