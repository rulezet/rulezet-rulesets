rule Win_Downloader_Small_1854
{
strings:
	$a0 = { 68b0204000e8a0f8ffff83c404e8a8f9ffffe84f000000 }


condition:
	$a0
}