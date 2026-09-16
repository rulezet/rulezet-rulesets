rule Win_Trojan_Flip_4
{
strings:
	$a0 = { 1fb91079b28481c1118feb012700970b0043eb }


condition:
	$a0
}