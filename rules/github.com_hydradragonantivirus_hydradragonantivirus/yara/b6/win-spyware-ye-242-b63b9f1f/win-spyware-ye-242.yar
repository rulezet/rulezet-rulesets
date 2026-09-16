rule Win_Spyware_ye_242
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]ef3df9ce0aa9dc8e305d00ea8a2f67 }


condition:
	$a0
}