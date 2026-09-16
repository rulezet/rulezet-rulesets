rule Win_Spyware_ye_127
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]7c428653973e6913bde28d7f274c04 }


condition:
	$a0
}