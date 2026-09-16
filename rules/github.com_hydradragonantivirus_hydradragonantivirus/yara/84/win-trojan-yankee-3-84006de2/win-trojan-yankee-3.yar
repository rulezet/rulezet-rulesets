rule Win_Trojan_Yankee_3
{
strings:
	$a0 = { de002e807f3800741cbe0a0003f31ebf0001b920000e1ff3a41f0e2eff7746061e50eb14908cda83c2102e031620 }


condition:
	$a0
}