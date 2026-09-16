rule Win_Spyware_ye_114
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]6fbd794e8a295c0eb0dd806a0aafe7 }


condition:
	$a0
}