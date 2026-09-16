rule Win_Trojan_TVED_3
{
strings:
	$a0 = { e800005e83ee03b44eb120ba470003d6cd21ba9e00b8013dcd21568bd6b91803bf180303febe0001 }


condition:
	$a0
}