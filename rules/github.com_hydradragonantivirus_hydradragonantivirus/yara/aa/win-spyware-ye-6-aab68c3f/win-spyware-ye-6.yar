rule Win_Spyware_ye_6
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]03c90dda1e45701a446914862e4b7b }


condition:
	$a0
}