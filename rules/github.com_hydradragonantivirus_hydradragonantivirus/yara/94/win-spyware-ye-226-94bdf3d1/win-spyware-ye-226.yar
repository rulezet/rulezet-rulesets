rule Win_Spyware_ye_226
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]df2de93efa99ccfea0cdf0dafa9fd7 }


condition:
	$a0
}