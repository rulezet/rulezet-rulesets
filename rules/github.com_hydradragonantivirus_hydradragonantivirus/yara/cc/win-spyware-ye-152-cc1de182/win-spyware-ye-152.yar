rule Win_Spyware_ye_152
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]955b9f74b0d782345e03ae18b8dd95 }


condition:
	$a0
}