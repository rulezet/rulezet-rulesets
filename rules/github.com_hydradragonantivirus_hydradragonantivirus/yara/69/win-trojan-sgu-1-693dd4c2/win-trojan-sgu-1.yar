rule Win_Trojan_SGU_1
{
strings:
	$a0 = { 6868a042008d85d0fcffff50e824f5ffff83c408684ca042008d85c8fbffff50e810f5ffff83c4080fb605e0f4420085c00f84df030000 }


condition:
	$a0
}