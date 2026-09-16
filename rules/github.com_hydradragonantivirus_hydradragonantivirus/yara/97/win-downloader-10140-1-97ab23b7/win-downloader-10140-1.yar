rule Win_Downloader_10140_1
{
strings:
	$a0 = { 558bec83c4f0b894344000e8dcfdffff6a006a00681435400068??3540006a00e82bffffff6a056814354000e86ffeffff }


condition:
	$a0
}