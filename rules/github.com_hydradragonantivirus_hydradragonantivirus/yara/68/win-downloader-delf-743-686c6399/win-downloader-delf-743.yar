rule Win_Downloader_Delf_743
{
strings:
	$a0 = { d0feffffbaa47f4000b8c47f4000e821feffff }


condition:
	$a0
}