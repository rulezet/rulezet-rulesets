rule Win_Trojan_Flipflop_1
{
strings:
	$a0 = { b91a008d966e03cd21c3b80242eb0490b8004233c933d2cd21c3b440b964028d960001cd21c3 }


condition:
	$a0
}