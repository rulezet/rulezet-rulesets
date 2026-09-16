rule Win_Spyware_ye_144
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]8d53976ca8cffaacd6fba610b0d58d }


condition:
	$a0
}