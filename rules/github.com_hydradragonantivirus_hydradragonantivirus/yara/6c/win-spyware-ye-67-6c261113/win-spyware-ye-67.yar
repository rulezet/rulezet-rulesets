rule Win_Spyware_ye_67
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]408e4a9f5b7a2d5f01aed13b5b7828 }


condition:
	$a0
}