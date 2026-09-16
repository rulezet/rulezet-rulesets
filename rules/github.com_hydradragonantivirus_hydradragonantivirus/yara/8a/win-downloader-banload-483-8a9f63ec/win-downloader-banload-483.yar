rule Win_Downloader_Banload_483
{
strings:
	$a0 = { 558bec83c4f0b868d94000e81074ffff6a016820da4000e85875ffffba78da4000b8a0da4000e895feffff84c0740c6a0068c8da4000 }


condition:
	$a0
}