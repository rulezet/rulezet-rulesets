rule Win_Spyware_ye_92
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]59a763b07413467012bfe2d4fc99c9 }


condition:
	$a0
}