rule Win_Downloader_Delf_713
{
strings:
	$a0 = { e8ecc4ffff33d2b8807f4000e8d0feffffbabc7f4000b8dc7f4000e821feffff84c0740c33d2b8bc7f4000e8b1feffff }


condition:
	$a0
}