rule Win_Trojan_R_31
{
strings:
	$a0 = { 01b44732d28db6f401cd2133ffb44e8d96a701cd2173118d96a401b43bcd217303e9de00b44eeb }


condition:
	$a0
}