rule Win_Downloader_VB_383
{
strings:
	$a0 = { 8b1868d04740008945e0e834f9ffff8bd08d4de8e83b7dfeff }


condition:
	$a0
}