rule Win_Trojan_R_9
{
strings:
	$a0 = { 8b86f3058dbe0301b96e0231054747e2fac33c0bbc0201e800008b2e0001bcfeff81edfb05be0e0603f5c604c3c604c6e8ccff }


condition:
	$a0
}