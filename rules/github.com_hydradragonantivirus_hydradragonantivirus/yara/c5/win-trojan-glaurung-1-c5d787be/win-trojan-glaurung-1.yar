rule Win_Trojan_Glaurung_1
{
strings:
	$a0 = { 0e1fb43cb903008d96ef01cd21721993b440bafa01b97700cd21b43ecd210e1f8d967102 }


condition:
	$a0
}