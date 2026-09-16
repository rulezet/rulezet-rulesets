rule Win_Trojan_TDSS_47
{
strings:
	$a0 = { 5a5e498d490249[0-100]495149[0-100]495149 }


condition:
	$a0
}