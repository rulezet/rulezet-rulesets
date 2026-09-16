rule Win_Trojan_Small_4439
{
strings:
	$a0 = { e800000000f84e4158504ed1d981c010000000ffe0 }


condition:
	$a0
}