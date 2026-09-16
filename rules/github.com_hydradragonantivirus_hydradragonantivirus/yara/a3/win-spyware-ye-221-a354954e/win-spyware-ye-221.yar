rule Win_Spyware_ye_221
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]da20e431f59ccff99bc0e3d5fd9aca }


condition:
	$a0
}