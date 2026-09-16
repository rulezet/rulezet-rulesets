rule Win_Trojan_VGEN_259
{
strings:
	$a0 = { 01b409cd211e33c08ed8813e000283eca30002c7069002eb081f7507ba1a02b409cd21baf001b43bcd21bd6b02 }


condition:
	$a0
}