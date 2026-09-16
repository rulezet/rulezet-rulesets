rule Win_Trojan_Peed_336
{
strings:
	$a0 = { 0fa20f31e8a000000068b8b000005981c1608d000081c1b8b0000068ae }


condition:
	$a0
}