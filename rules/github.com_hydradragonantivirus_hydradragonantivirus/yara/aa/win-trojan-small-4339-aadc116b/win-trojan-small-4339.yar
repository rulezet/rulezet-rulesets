rule Win_Trojan_Small_4339
{
strings:
	$a0 = { e848000000e87b000000e91a0000000f851400000081c664f6ffffffe6555ab84a32ffaae94f000000 }


condition:
	$a0
}