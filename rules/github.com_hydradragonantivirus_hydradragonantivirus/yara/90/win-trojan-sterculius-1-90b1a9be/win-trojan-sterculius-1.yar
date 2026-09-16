rule Win_Trojan_Sterculius_1
{
strings:
	$a0 = { 03003c213e5e83ee0356fc83c653bf0001a5a55eba4559b801facd2133c08ec0bfe00126817d035354741cb90a01f3 }


condition:
	$a0
}