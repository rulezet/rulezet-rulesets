rule Win_Spyware_ye_14
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]0bd115e2264d78224c711c8e365303 }


condition:
	$a0
}