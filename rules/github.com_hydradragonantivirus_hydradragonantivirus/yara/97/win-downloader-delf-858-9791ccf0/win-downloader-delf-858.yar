rule Win_Downloader_Delf_858
{
strings:
	$a0 = { 558bec83c4f0b8d87e4000e8ecc4ffffba747f4000b8947f4000e82dfeffff84c0740c33d2b8747f }


condition:
	$a0
}