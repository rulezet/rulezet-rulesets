rule Win_Trojan_Immigran_1
{
strings:
	$a0 = { bc02ba00008e5d638b5d37cd26ba2600b409cd21b8004ccd2100020d0a4465636f64696e67 }


condition:
	$a0
}