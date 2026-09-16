rule Win_Trojan_MSU4_1
{
strings:
	$a0 = { e6fc81fafe10d0eeb2ae8b16a4b4d0ee43f8f8fbf7da4ae4a4b2e83be381c208183ceab288d0ee81fa08188b1e }


condition:
	$a0
}