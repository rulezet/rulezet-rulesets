rule Win_Downloader_Small_2014
{
strings:
	$a0 = { 6a006a006a006a0068003040008b85e8fbffff50ff1528204000 }


condition:
	$a0
}