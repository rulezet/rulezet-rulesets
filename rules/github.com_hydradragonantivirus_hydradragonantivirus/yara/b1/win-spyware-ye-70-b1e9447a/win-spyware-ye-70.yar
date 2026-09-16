rule Win_Spyware_ye_70
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]43894d9a5e05b0da842954466e0bbb }


condition:
	$a0
}