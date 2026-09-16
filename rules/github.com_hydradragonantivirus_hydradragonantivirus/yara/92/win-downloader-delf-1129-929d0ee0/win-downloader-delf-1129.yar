rule Win_Downloader_Delf_1129
{
strings:
	$a0 = { 558bec83c4f0b8bc874000e8e4c2ffff6a03685c884000e8f4c3ffffba????4000b8??884000e8b5feffff84c0740c6a0068c8884000e8d5c3ffff }


condition:
	$a0
}