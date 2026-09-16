rule Win_Spyware_ye_122
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]7745815692316416b8e5887212b7ef }


condition:
	$a0
}