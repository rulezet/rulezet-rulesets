rule Win_Trojan_Keyb_2
{
strings:
	$a0 = { 1700e81200fe069c04b80103b9010033dbba8000cd12c3b110b82e00e670e47186f0b02fe6 }


condition:
	$a0
}