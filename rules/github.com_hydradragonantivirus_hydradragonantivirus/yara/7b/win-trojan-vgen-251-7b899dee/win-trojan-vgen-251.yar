rule Win_Trojan_VGEN_251
{
strings:
	$a0 = { e8ed03b9edfdc9163b041a7d45c61e45bf09c3f1421427ce1808a01818a19c1da71e20ec3151119a3d27a59f8a }


condition:
	$a0
}