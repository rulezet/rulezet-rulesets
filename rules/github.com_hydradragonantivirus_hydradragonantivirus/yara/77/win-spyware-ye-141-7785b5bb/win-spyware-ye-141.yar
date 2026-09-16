rule Win_Spyware_ye_141
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]8a509461a5ccffa9cbf09305adcafa }


condition:
	$a0
}