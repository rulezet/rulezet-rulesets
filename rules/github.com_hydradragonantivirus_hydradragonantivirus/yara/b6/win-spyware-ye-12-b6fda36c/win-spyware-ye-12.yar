rule Win_Spyware_ye_12
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]09d713e024437620426f12842c4979 }


condition:
	$a0
}