rule Win_Spyware_ye_11
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]08d612e72342752749761983234070 }


condition:
	$a0
}