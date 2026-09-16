rule Win_Spyware_ye_241
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]ee3cf8cd09a8d3852f5c07f191366e }


condition:
	$a0
}