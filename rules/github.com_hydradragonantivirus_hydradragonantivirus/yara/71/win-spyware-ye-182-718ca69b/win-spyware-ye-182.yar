rule Win_Spyware_ye_182
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]b379bd0acef5a0caf499c4365e7b2b }


condition:
	$a0
}