rule Win_Trojan_Small_4451
{
strings:
	$a0 = { e804000000??????00588b00505068ec6905f0e8630000005268 }


condition:
	$a0
}