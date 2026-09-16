rule Win_Spyware_ye_33
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]1eec28fd395803b5df8c37a1c1e69e }


condition:
	$a0
}