rule Win_Trojan_VGEN_721
{
strings:
	$a0 = { e80000cc5d81ed06018db67f02bf0001a5a4c686cc0200b44732d28db68c02cd21b41a8d96cd02cd21b44eb90700fe8e }


condition:
	$a0
}