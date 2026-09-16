rule Win_Trojan_Inch_1
{
strings:
	$a0 = { 03008b560081c28100cd2133c933d2b80242cd21b4408b959300b96d01cd21b801578b4d17 }


condition:
	$a0
}