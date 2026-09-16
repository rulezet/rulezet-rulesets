rule Win_Trojan_Trivial_527
{
strings:
	$a0 = { cd21b74093ba0001b11ecd21c32a2e2a00 }


condition:
	$a0
}