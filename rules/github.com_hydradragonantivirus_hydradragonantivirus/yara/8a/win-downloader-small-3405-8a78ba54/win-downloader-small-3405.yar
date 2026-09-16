rule Win_Downloader_Small_3405
{
strings:
	$a0 = { 6a008d9424080100006a008d44240852506a006a00ff1548204000 }


condition:
	$a0
}