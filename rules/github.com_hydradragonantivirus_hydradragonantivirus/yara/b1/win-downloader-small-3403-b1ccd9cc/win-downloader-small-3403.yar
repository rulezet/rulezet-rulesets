rule Win_Downloader_Small_3403
{
strings:
	$a0 = { 6800301413e87f000000be0b301413bf3d301413ba05000000 }


condition:
	$a0
}