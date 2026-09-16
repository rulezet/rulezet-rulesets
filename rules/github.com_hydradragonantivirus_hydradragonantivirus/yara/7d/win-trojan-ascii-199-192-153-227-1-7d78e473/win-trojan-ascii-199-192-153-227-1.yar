rule Win_Trojan_Ascii_199_192_153_227_1
{
strings:
	$a0 = { 3139392e3139322e3135332e323237 }


condition:
	$a0
}