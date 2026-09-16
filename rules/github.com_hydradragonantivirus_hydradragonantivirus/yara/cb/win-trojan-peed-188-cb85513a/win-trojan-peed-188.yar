rule Win_Trojan_Peed_188
{
strings:
	$a0 = { 558bec83ec30535657f7db0fbed42bf323c22bdb2bca23dd2bc9 }


condition:
	$a0
}