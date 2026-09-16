rule Win_Trojan_CP_1
{
strings:
	$a0 = { 03d10536ffa313fcb6071d80b3f2aeebf483c7038bf735202c91f6d08600abb3fcd12baae61f4f }


condition:
	$a0
}