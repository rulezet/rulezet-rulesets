rule Win_Trojan_VGEN_105
{
strings:
	$a0 = { ed038db6c300bf000157a5a4b98000be80008dbeec00f3a4b44eb927008d96bd00cd217320b42ccd2180fd0575f7 }


condition:
	$a0
}