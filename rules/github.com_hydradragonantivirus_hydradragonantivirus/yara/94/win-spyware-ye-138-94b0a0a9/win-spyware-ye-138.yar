rule Win_Spyware_ye_138
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]87559166a2c1f4a6c8f59802a2c7ff }


condition:
	$a0
}