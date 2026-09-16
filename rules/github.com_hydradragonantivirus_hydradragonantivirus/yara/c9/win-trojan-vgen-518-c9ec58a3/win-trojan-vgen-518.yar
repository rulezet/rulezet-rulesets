rule Win_Trojan_VGEN_518
{
strings:
	$a0 = { 60e8000087f75e83ee065681c6e100a5a5b41a5a528bfa81c2e500cd218bd781c2db00fcb44eb92000cd21720bb4 }


condition:
	$a0
}