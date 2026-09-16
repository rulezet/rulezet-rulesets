rule Win_Spyware_ye_190
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]bb01c512d6fda8d2fca1cc3e6603b3 }


condition:
	$a0
}