rule Win_Downloader_Small_2062
{
strings:
	$a0 = { 687488703a2fe275ea6463613a2e6d673430732766bf5e3bfc532f34e7a1 }


condition:
	$a0
}