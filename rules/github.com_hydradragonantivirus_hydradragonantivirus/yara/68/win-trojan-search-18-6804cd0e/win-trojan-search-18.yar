rule Win_Trojan_Search_18
{
strings:
	$a0 = { 01a0e3032ea20101a0e4032ea20201eb0190b500b11c }


condition:
	$a0
}