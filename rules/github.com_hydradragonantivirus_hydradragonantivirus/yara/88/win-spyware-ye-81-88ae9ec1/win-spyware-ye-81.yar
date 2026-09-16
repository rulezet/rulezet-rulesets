rule Win_Spyware_ye_81
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]4e9c58ad6908b3e58f3c675171164e }


condition:
	$a0
}