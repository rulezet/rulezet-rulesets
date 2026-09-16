rule Win_Spyware_ye_237
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]ea30f4c105acdf892b5073650daada }


condition:
	$a0
}