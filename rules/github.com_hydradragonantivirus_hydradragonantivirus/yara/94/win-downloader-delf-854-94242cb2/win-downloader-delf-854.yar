rule Win_Downloader_Delf_854
{
strings:
	$a0 = { 558bec83c4f0b8d87e4000e8ecc4ffff33d2b8807f4000e8d0feffffba??7f4000b8????4000e821feffff84c0740c33d2b8??7f4000e8b1feffffe88cb5ffffffffffff??000000687474703a2f2f }


condition:
	$a0
}