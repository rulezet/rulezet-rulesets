rule Win_Trojan_JDC_4
{
strings:
	$a0 = { e8000006bb00bb8ec333db26c6070f26803f0f750a26c607ff268037ff741133db43b701268037ac80c30280fb0075 }


condition:
	$a0
}