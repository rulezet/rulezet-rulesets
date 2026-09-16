rule Win_Downloader_Small_3446
{
strings:
	$a0 = { 6c7361dfcbbffd73732e65786513433a5c6762766464 }


condition:
	$a0
}