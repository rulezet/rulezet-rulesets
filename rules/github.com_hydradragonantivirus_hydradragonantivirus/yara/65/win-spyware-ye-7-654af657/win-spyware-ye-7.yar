rule Win_Spyware_ye_7
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]04ca0edb1f46711b456a15872f540c }


condition:
	$a0
}