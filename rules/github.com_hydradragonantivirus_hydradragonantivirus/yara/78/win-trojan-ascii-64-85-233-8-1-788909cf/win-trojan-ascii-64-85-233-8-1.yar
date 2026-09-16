rule Win_Trojan_Ascii_64_85_233_8_1
{
strings:
	$a0 = { 36342e38352e3233332e38 }


condition:
	$a0
}