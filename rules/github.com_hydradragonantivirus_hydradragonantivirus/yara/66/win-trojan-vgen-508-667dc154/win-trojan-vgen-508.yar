rule Win_Trojan_VGEN_508
{
strings:
	$a0 = { 4e654b5351e800005e83ee0956fcbf0001b90500f3a4e9b4019c0e2eff16c008c3fb80fc4b743980fc11740880fc12 }


condition:
	$a0
}