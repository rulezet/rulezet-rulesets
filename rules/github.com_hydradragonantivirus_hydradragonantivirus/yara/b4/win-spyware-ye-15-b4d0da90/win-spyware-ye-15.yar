rule Win_Spyware_ye_15
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]0cd216e3274e79234d721d8f375c14 }


condition:
	$a0
}