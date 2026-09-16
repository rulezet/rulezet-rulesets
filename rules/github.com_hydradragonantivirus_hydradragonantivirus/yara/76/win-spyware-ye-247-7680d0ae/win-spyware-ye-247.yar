rule Win_Spyware_ye_247
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]f43afecb0fb6e18b355a05f79fc4fc }


condition:
	$a0
}