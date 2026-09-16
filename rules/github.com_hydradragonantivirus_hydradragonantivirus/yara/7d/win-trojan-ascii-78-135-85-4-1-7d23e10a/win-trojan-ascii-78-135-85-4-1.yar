rule Win_Trojan_Ascii_78_135_85_4_1
{
strings:
	$a0 = { 37382e3133352e38352e34 }


condition:
	$a0
}