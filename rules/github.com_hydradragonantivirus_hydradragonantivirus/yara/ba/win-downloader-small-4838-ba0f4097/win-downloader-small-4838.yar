rule Win_Downloader_Small_4838
{
strings:
	$a0 = { 558bec83ec5456576a4433f65f8d45ac575650e8????????83c40c897dac668975dce8 }


condition:
	$a0
}