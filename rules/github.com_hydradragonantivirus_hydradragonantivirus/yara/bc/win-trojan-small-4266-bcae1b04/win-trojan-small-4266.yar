rule Win_Trojan_Small_4266
{
strings:
	$a0 = { 558bec6aff685821400068601b400064a1000000005064892500000000 }


condition:
	$a0
}