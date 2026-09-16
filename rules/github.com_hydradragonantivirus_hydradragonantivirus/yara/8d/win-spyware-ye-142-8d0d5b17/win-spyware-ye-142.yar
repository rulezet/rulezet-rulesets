rule Win_Spyware_ye_142
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]8b519562a6cdf8a2ccf19c0eb6d383 }


condition:
	$a0
}