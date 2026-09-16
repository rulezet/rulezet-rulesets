rule Win_Trojan_Dropper_62
{
strings:
	$a0 = { c83f68c871a9642c716f6f3f2364cc64c8256f64646f6436acd764a93f6bccbe5e5e78afededededededed6769edede5 }


condition:
	$a0
}