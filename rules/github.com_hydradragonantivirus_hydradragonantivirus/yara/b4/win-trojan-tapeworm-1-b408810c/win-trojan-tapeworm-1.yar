rule Win_Trojan_Tapeworm_1
{
strings:
	$a0 = { 010e1f2e803e182b01741333d2b97707b4402e8b1ea204cd219090e8a001b442b0002e8b1ea2 }


condition:
	$a0
}