rule Win_Downloader_Small_1992
{
strings:
	$a0 = { 74236a006a0057566a00e81d0000006a0557e86f000000 }


condition:
	$a0
}