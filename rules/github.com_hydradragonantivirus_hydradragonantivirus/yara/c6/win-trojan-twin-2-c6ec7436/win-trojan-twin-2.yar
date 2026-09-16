rule Win_Trojan_Twin_2
{
strings:
	$a0 = { ffcd213c077507e82300b44ccd21b82135cd212e891e }


condition:
	$a0
}