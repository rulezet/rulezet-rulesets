rule Win_Spyware_ye_128
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]7d43875c983f6a1c466b168020457d }


condition:
	$a0
}