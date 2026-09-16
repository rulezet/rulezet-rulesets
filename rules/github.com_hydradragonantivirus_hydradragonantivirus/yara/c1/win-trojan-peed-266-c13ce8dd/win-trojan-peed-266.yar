rule Win_Trojan_Peed_266
{
strings:
	$a0 = { f80f31e99c0000006890b000005981c1408d000081c190b0000068ae }


condition:
	$a0
}