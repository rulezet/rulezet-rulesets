rule Win_Trojan_Trivial_469
{
strings:
	$a0 = { b44eb90100cd217302eb1cba9e00b8023dcd2172128bd8e80f00ba8000b44fcd217302eb02ebe4cd20ba0001b440b94100cd21b43ecd21c3 }


condition:
	$a0
}