rule Win_Trojan_VGEN_399
{
strings:
	$a0 = { e800005e83ee0956fcbf0001b90500f3a4e9b4019c0e2eff16c008c3fb80fc4b743980fc11740880fc127403e98b01 }


condition:
	$a0
}