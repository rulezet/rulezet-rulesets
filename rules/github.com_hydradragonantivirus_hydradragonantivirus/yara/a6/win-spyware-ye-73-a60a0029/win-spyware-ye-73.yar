rule Win_Spyware_ye_73
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]469450a56100abdd87345f49690e46 }


condition:
	$a0
}