rule Win_Spyware_ye_232
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]e52befc400a7d2842e537e6808ade5 }


condition:
	$a0
}