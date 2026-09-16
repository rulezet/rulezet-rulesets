rule Win_Spyware_ye_30
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]1be125f2365d08b2dc812c9ec6e393 }


condition:
	$a0
}