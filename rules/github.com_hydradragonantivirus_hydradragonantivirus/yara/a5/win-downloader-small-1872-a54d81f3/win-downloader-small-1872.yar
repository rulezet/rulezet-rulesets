rule Win_Downloader_Small_1872
{
strings:
	$a0 = { 8d85ccfeffff68d011a02a50e8010014da8d85ccfeffff50e8010009f3 }


condition:
	$a0
}