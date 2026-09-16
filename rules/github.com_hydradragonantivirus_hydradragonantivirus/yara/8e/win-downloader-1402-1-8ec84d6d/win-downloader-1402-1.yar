rule Win_Downloader_1402_1
{
strings:
	$a0 = { 55685781400064ff30648920[0-230]6a016a006a00a1d0a74000e852b9ffff5068d88140006a00e881fdffff }


condition:
	$a0
}