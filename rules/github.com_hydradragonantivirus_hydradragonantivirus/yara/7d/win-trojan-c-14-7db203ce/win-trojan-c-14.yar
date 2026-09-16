rule Win_Trojan_C_14
{
strings:
	$a0 = { e90000e800005d81ed0701b4098d96bd01cd218db6c902bf0001fca5a5b42fcd212e899ed7022e8c86d902b41a8d96db02cd21b44eb922008d96cd02eb02b44fcd2172 }


condition:
	$a0
}