rule Win_Downloader_Small_1338
{
strings:
	$a0 = { 7afe61fc54f046786938654106633a5c7765cf2c730e74616b6d677254 }


condition:
	$a0
}