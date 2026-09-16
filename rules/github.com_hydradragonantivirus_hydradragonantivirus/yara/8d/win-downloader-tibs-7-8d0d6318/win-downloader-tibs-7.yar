rule Win_Downloader_Tibs_7
{
strings:
	$a0 = { 8d12dde2d81424baffffffffdde5 }


condition:
	$a0
}