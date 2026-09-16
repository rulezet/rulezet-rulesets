rule Win_Trojan_VGEN_301
{
strings:
	$a0 = { 5d81ed05018db65c01bf000157a5a4b41a8d96ef01cd218d968501b44eb90700cd21722be85f00b43f8d961a02 }


condition:
	$a0
}