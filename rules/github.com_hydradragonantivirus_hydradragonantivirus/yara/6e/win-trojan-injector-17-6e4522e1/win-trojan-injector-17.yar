rule Win_Trojan_Injector_17
{
strings:
	$a0 = { 60be005041008dbe00c0feff5789e58d9c2480c1ffff31c05039dc75fb4646536887a303005783c3045368e371020056 }


condition:
	$a0
}