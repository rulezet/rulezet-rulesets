rule Win_Spyware_ye_204
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]c917d320e483366002afd2c4ec8939 }


condition:
	$a0
}