rule Win_Trojan_Espacio_1
{
strings:
	$a0 = { c08ed0bc0001e80000582d0e00b104d3e803c32d1000bb22015053cbb0013c00750e26c7060001e91426c70602 }


condition:
	$a0
}