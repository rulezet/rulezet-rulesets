rule Win_Spyware_ye_98
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]5fad69be7a194c7e204d705a7a1f57 }


condition:
	$a0
}