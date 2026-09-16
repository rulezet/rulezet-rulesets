rule Win_Trojan_Bancos_906
{
strings:
	$a0 = { 3477ef431af7e42a13f3cd8fc0dd0c505db14a9eb60dbff7aefbcd90b712c26b54555f507c2ebf7a825cfee522dcf914a7e18563ccfbe6374a56a6ae6f1a2740 }


condition:
	$a0
}