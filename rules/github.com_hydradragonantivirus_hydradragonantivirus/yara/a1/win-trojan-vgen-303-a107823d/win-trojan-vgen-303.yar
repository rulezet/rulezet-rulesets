rule Win_Trojan_VGEN_303
{
strings:
	$a0 = { 5d81ed03011e060e1f0e078db679018dbe7101a5a5a5a5b41a8d967d02cd218d967702b44eb90700cd217220b0 }


condition:
	$a0
}