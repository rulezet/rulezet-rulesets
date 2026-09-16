rule Win_Trojan_Zlodic_1
{
strings:
	$a0 = { f6b96e023e8aa2330132e03e88a23301463bf17702ebed }


condition:
	$a0
}