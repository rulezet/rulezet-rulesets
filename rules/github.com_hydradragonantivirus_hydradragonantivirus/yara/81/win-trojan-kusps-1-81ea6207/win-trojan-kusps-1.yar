rule Win_Trojan_Kusps_1
{
strings:
	$a0 = { 50e800005e81ee19028cc32e019c8a022e019c8c02b8abafcd213da9ce7449064b8ec326803e00005a753c26a103002d }


condition:
	$a0
}