rule Win_Trojan_VGEN_517
{
strings:
	$a0 = { 032e80bea4005a7410bf0001bea30003f557a5a5a4e81e00c38cc0051000502e01463ae8100058050000fa8ed0 }


condition:
	$a0
}