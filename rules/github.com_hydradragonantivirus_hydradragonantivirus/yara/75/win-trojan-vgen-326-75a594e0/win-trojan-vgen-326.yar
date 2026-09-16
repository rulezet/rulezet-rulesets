rule Win_Trojan_VGEN_326
{
strings:
	$a0 = { 01e88c0133c9b11451ba4901b43c33c9cd2193be0102bf4d0fb401b9a000e8a50cb440ba4d0fcd21b43ecd21a1 }


condition:
	$a0
}