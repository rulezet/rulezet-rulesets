rule Win_Downloader_Tibs_4
{
strings:
	$a0 = { df242489ed87ff6800a2400058da3424 }


condition:
	$a0
}