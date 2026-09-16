rule Win_Downloader_Small_1891
{
strings:
	$a0 = { 558bec83c4f0b838114000e8d0feffff68a0114000e896ffffff6a006a0068c411400068d41140006a00e879ffffff }


condition:
	$a0
}