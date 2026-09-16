rule Win_Spyware_ye_257
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]fecc08dd19b8e3953f6c178121467e }


condition:
	$a0
}