rule Win_Downloader_Banload_583
{
strings:
	$a0 = { 558bec83c4f0b868d94000e81074ffff6a016820da4000e85875ffffba????????????da4000e895feffff84c0740c6a0068??da4000e83975ffff }


condition:
	$a0
}