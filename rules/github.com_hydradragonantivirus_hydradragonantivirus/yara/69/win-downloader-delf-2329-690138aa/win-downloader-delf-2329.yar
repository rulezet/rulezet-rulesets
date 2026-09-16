rule Win_Downloader_Delf_2329
{
strings:
	$a0 = { 558becb90c0000006a006a004975f951b868724100e812e3feff33c055687075410064ff306489 }


condition:
	$a0
}