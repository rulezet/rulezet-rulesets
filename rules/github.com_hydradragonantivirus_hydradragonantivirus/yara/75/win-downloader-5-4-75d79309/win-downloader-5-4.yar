rule Win_Downloader_5_4
{
strings:
	$a0 = { e8a833ffff33d2b868214100e8a0feffffbaac214100b8d0214100e8f1fdffff84c0740c33d2b8ac214100e881feffff }


condition:
	$a0
}