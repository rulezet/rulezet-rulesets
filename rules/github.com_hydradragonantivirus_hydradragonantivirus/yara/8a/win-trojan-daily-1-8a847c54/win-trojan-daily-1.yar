rule Win_Trojan_Daily_1
{
strings:
	$a0 = { 558bec83c4ec535657a188924000c60001b810804000e809c6ffffe854fbffff }


condition:
	$a0
}