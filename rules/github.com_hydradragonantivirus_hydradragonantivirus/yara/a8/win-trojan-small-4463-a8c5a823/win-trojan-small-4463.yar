rule Win_Trojan_Small_4463
{
strings:
	$a0 = { b84f1040002500f0ffff6681384d5a740a0500f0ffffebf22564000fb75812e8 }


condition:
	$a0
}