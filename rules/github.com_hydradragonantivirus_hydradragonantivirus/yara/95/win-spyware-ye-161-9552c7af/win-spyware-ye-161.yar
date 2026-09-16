rule Win_Spyware_ye_161
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]9e6ca87db9d883355f0cb72141661e }


condition:
	$a0
}