rule Win_Spyware_ye_225
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]de2ce83df998c3f59fccf7e181265e }


condition:
	$a0
}