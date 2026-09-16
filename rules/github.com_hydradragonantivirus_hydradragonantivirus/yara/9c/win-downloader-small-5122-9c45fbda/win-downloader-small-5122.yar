rule Win_Downloader_Small_5122
{
strings:
	$a0 = { ff34bd8078410068b07c4100e8a321000083c4086a016a006a0068b07c41006a006a00e8141c0000 }


condition:
	$a0
}