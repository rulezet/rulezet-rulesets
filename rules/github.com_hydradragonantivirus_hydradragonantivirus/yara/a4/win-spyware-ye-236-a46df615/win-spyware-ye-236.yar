rule Win_Spyware_ye_236
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]e937f3c004a3d680224f72640ca9d9 }


condition:
	$a0
}