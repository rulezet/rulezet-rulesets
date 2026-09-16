rule Win_Trojan_Weed_8
{
strings:
	$a0 = { b841018ed88ec033dbb403cd108916fffb5f011e069a05002109071fedf809b400cd1ffe1a87 }


condition:
	$a0
}