rule Win_Spyware_ye_21
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]12d81ce92d5407b1d3f89b0db5d282 }


condition:
	$a0
}