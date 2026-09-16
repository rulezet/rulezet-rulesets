rule Win_Trojan_VGEN_668
{
strings:
	$a0 = { cd213dcaca744fb82135cd212e891e62012e8c0664018cd8488ec026a103002d1a0093b44a1e07cd21b448bb19 }


condition:
	$a0
}