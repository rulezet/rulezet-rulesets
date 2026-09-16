rule Win_Trojan_VCL_MUT_6
{
strings:
	$a0 = { cd21538bec81ec800052b41a8d56809393cd21b44eb927005acd217209e80f007304b44feb }


condition:
	$a0
}