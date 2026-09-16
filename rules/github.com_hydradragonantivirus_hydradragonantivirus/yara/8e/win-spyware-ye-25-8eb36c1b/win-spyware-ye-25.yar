rule Win_Spyware_ye_25
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]16e420f531507b2d5704af19b9de96 }


condition:
	$a0
}