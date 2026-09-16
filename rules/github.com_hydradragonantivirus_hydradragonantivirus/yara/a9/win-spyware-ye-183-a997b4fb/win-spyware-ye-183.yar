rule Win_Spyware_ye_183
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]b47abe0bcff6a1cbf59ac5375f04bc }


condition:
	$a0
}