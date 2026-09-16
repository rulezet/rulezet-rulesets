rule Win_Spyware_ye_37
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]22e82cf93d6417416308ab1d456212 }


condition:
	$a0
}