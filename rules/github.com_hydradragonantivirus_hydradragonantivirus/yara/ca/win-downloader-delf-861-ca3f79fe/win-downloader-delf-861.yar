rule Win_Downloader_Delf_861
{
strings:
	$a0 = { 558bec83c4f0b8d87e4000e8ecc4ffff33d2b8807f4000e8d0feffffbaac7f4000b8e87f4000e821feffff }


condition:
	$a0
}