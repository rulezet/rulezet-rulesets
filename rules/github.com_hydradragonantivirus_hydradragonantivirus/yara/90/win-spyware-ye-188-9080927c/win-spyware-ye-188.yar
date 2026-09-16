rule Win_Spyware_ye_188
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]b907c310d4f3a6d0f29fc2345c7929 }


condition:
	$a0
}