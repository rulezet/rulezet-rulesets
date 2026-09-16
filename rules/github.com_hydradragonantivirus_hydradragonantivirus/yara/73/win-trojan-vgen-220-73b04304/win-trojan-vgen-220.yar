rule Win_Trojan_VGEN_220
{
strings:
	$a0 = { ed06018db68a02bf0001a5a43ec686d70200b44732d28db69702cd21b41a8d96d802cd21b44eb907003efe8e90 }


condition:
	$a0
}