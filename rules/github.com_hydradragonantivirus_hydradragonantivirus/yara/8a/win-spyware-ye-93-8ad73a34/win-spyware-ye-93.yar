rule Win_Spyware_ye_93
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]5aa064b1751c4f791b4063557d1a4a }


condition:
	$a0
}