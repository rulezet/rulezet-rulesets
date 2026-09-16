rule Win_Spyware_ye_18
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]0fdd19ee2a497c2e507d208a2a4f07 }


condition:
	$a0
}