rule Win_Trojan_Peed_154
{
strings:
	$a0 = { e81100000089daf7da01d0ba2800000083f800744fc35ae80000000029d287d15a8d1d16 }


condition:
	$a0
}