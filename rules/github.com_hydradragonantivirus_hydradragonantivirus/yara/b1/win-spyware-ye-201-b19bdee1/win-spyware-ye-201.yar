rule Win_Spyware_ye_201
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]c614d025e1802b5d07b4dfc9e98ec6 }


condition:
	$a0
}