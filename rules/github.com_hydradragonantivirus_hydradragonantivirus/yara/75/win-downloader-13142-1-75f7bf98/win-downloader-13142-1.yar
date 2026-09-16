rule Win_Downloader_13142_1
{
strings:
	$a0 = { 558bec83c4f0b8b8354000e83cfdffff33c05568??36400064ff30648920e819efffff6a0168??364000e8d1fdffff }


condition:
	$a0
}