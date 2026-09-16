rule Win_Trojan_FaxFree_1
{
strings:
	$a0 = { 2acd2180fe05730b33c05007b8110026a3fe03e948fd90b44ccd21003906ac027406c706ac02ff }


condition:
	$a0
}