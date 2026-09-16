rule Win_Downloader_Small_2024
{
strings:
	$a0 = { 6a006a006a006a0068003040008b8de8fbffff51ff1530204000 }


condition:
	$a0
}