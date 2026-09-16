rule Win_Spyware_ye_250
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]f7c501d612b1e496386508f292376f }


condition:
	$a0
}