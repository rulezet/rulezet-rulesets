rule Win_Trojan_VGEN_242
{
strings:
	$a0 = { a300c800010068e01a9a3f02a300a3fa018916fc016800209a3f02a300a3fe01891600028dbe00ff16576a009a }


condition:
	$a0
}