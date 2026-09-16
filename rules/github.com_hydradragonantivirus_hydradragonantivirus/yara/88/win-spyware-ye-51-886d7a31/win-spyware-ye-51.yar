rule Win_Spyware_ye_51
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]30fe3a8f4b6a1d4f711e41abcbe898 }


condition:
	$a0
}