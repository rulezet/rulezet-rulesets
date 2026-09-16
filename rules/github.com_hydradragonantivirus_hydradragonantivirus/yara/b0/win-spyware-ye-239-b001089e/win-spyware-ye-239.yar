rule Win_Spyware_ye_239
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]ec32f6c307aed9832d527d6f17bcf4 }


condition:
	$a0
}