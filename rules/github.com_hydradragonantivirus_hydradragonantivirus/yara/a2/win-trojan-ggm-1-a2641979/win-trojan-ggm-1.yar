rule Win_Trojan_GGM_1
{
strings:
	$a0 = { 1e06e80200eb0b8bdc368b2f83ed068bc4c30e582e2b86d1002e8986d10016582d3f002e8986cb00b8036390903dff }


condition:
	$a0
}