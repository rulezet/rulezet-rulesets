rule Win_Spyware_ye_113
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]6ebc784d89285305afdc877111b6ee }


condition:
	$a0
}