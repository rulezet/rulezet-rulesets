rule Win_Trojan_Goodluck_1
{
strings:
	$a0 = { 01bf0002b99600f3a58ed8ba3b02b82125cd210e58be }


condition:
	$a0
}