rule Win_Downloader_10770_1
{
strings:
	$a0 = { 558bec83c4f0b88c394000e8a8fcffffe82ffeffffe8fef4ffff8bc000000000 }


condition:
	$a0
}