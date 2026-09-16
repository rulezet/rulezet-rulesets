rule Win_Spyware_ye_240
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]ed33f7cc08afda8c365b06f090356d }


condition:
	$a0
}