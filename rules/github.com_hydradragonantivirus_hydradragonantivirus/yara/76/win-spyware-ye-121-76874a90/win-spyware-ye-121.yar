rule Win_Spyware_ye_121
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]7644805591305b0db7e48f7919bef6 }


condition:
	$a0
}