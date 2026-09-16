rule Win_Spyware_ye_156
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]9967a370b4d38630527f22943c5909 }


condition:
	$a0
}