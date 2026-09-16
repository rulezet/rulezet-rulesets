rule Win_Trojan_AntiGUS_1
{
strings:
	$a0 = { bf0506fcb0d9be1900902e30049090464f9075f5fceb00 }


condition:
	$a0
}