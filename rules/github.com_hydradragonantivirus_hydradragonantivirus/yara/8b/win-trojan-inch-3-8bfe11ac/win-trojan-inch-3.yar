rule Win_Trojan_Inch_3
{
strings:
	$a0 = { 408b3e5a008b9d8d00b90a008b165a0081c28100cd218b3e5a008b9d8d0033c933d2b80242cd21 }


condition:
	$a0
}