rule Win_Spyware_ye_26
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]17e521f6325104b6d885289232570f }


condition:
	$a0
}