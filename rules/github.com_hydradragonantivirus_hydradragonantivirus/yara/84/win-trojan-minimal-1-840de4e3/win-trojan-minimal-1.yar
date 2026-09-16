rule Win_Trojan_Minimal_1
{
strings:
	$a0 = { 7101b44eb90100cd217302eb10e80f00ba8000b44fcd217302eb02ebf0cd20ba9e00b80043cd21890e7b0133c9b80143cd21b8023dcd2172e48bd8b80057cd }


condition:
	$a0
}