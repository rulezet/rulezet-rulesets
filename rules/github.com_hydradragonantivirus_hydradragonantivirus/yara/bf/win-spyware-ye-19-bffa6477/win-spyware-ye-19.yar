rule Win_Spyware_ye_19
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]10de1aef2b4a7d2f517e218b2b4878 }


condition:
	$a0
}