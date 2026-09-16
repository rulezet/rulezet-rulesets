rule Win_Spyware_ye_202
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]c715d126e281346608b5d8c2e2873f }


condition:
	$a0
}