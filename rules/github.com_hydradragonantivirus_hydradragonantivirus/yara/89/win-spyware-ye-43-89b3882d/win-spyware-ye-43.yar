rule Win_Spyware_ye_43
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]28f63287436215476916b923436010 }


condition:
	$a0
}