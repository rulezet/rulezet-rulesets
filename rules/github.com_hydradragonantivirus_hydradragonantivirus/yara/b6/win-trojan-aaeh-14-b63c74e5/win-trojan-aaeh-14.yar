rule Win_Trojan_AAEH_14
{
strings:
	$a0 = { 2d433030302d79617962746a79 }

	$a1 = { a7f7ffff898570ffffff6a006a036a016a008d45bc506a106880080000e80442ffff83c41c8d45c050e8a286ffff8985 }


condition:
	$a0 and $a1
}