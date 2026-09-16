rule Win_Trojan_Vesna_6
{
strings:
	$a0 = { c70687053a008b1e2601b4428b0e1c018b161e01b000e85bfbb4408d167e05b93a00e84ffb }


condition:
	$a0
}