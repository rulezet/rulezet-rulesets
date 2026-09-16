rule Win_Trojan_Detic_1
{
strings:
	$a0 = { 058bde5003f12e8a47012e300743e2f6582e3004eb12 }


condition:
	$a0
}