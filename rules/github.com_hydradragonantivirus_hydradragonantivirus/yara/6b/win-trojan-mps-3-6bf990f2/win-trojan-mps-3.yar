rule Win_Trojan_MPS_3
{
strings:
	$a0 = { cd27a12c008ed833ff8b05470bc075f9 }


condition:
	$a0
}