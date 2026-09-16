rule Win_Spyware_ye_174
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]ab71b502c6ed98c2ec913caed6f3a3 }


condition:
	$a0
}