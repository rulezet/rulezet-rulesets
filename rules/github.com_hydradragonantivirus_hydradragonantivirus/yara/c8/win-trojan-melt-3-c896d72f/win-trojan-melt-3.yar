rule Win_Trojan_Melt_3
{
strings:
	$a0 = { 8b450c83c0088b10528b450c83c0048b105268d68a040868d09b0408e82ffbffff83c4108b45e850e8d3fbffff83c40431c0eb00 }

	$a1 = { 79206d336c742c2046 }


condition:
	$a0 and $a1
}