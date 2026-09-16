rule Win_Trojan_Chaos_1
{
strings:
	$a0 = { baf904b440e8b300595ab80042e8ab00720b33d2b9dc0490b440e89e008b0ee8048b16ea04 }


condition:
	$a0
}