rule Win_Spyware_ye_133
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]82488c599dc4f7a1c3e88b7d254272 }


condition:
	$a0
}