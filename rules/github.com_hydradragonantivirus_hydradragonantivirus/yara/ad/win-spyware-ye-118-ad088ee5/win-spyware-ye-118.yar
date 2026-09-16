rule Win_Spyware_ye_118
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]73b97d4a8e35600ab4d984761ebbeb }


condition:
	$a0
}