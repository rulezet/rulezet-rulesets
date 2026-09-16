rule Win_Trojan_VGEN_519
{
strings:
	$a0 = { 1e60e8000087f75e83ee065681c61c01a5a5b41a5a528bfa81c22001cd218bd781c21601fcb44eb92000cd21720bb4 }


condition:
	$a0
}