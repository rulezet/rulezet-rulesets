rule Win_Downloader_Tibs_6
{
strings:
	$a0 = { 8d128d3f87c9da3c24d90424 }


condition:
	$a0
}