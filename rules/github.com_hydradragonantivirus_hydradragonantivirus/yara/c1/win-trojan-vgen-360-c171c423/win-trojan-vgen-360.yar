rule Win_Trojan_VGEN_360
{
strings:
	$a0 = { 01be0f01b187ac3400aae2fa90e440a20a01be0001b90f00f3a4c6060e01c3e8dfffb44eb127ba7f01cd217227b8 }


condition:
	$a0
}