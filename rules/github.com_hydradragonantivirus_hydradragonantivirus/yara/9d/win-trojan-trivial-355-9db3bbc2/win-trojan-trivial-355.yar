rule Win_Trojan_Trivial_355
{
strings:
	$a0 = { 01b44eb92000cd217220ba9e00b8013dcd218bd8b440b94e00ba0001cd21720ab43ecd21b44f }


condition:
	$a0
}