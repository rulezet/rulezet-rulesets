rule Win_Spyware_ye_27
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]18e622f7335205b7d9862993335000 }


condition:
	$a0
}