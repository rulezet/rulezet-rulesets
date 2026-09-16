rule Win_Trojan_Dikshev_28
{
strings:
	$a0 = { 4eb19e87cecd217301c38bd6ac3c2e75fbc704636fc644026db45bcd2172ea93b440ba320087d1ebdc }


condition:
	$a0
}