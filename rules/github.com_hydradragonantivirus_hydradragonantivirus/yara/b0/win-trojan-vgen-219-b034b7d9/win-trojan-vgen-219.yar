rule Win_Trojan_VGEN_219
{
strings:
	$a0 = { 81ed06018db68902bf0001a5a43ec686d60200b44732d28db69602cd21b41a8d96d702cd21b44eb907003efe8e8f }


condition:
	$a0
}