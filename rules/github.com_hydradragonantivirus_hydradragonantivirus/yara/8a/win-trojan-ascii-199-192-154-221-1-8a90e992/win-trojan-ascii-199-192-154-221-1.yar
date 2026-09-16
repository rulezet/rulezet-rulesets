rule Win_Trojan_Ascii_199_192_154_221_1
{
strings:
	$a0 = { 3139392e3139322e3135342e323231 }


condition:
	$a0
}