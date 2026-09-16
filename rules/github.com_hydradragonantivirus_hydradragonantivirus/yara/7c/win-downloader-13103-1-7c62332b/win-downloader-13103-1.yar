rule Win_Downloader_13103_1
{
strings:
	$a0 = { 558bec83c4f0b814394000e814fbffffb890394000e896fdffffe889feffffe8c4f4ffff }


condition:
	$a0
}