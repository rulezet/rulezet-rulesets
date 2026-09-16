rule Win_Trojan_Reset_1
{
strings:
	$a0 = { 01cf3d004b741480fc43740f80fc56740a80fc3d }


condition:
	$a0
}