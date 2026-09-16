rule Win_Trojan_Mangel_1
{
strings:
	$a0 = { 52baa50583f2ff8bcaf7d15a99cd18b910002e2b0e6d05b440cd18b42ccd188af231164c0531 }


condition:
	$a0
}