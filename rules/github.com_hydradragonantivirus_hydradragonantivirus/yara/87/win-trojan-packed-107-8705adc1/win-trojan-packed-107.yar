rule Win_Trojan_Packed_107
{
strings:
	$a0 = { ba00000000bf17414100fe074781ff2543410075f54281fa9f97010075e7f1f1 }


condition:
	$a0
}