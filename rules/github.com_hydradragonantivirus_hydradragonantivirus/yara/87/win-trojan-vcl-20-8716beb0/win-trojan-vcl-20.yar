rule Win_Trojan_VCL_20
{
strings:
	$a0 = { ed06018db6bb0101010157a5a48b966a0233d289966a02e81001e81e011acd8d96ac02210e8d966002b44eb90700 }


condition:
	$a0
}