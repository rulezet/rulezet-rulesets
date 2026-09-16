rule Win_Trojan_TheLoader_1
{
strings:
	$a0 = { b500b6008a160000cd13ba3600b409cd21fe060000ebe0b002b9bc02ba00008e5d638b5d37cd }


condition:
	$a0
}