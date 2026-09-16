rule Win_Trojan_Korvs_1
{
strings:
	$a0 = { 02b9b6000e1f80340090464975f8fec0eb003c0a7404e2f6ebf4ba2601c6062d0100eb0c2a2e636f6d000000002e }


condition:
	$a0
}