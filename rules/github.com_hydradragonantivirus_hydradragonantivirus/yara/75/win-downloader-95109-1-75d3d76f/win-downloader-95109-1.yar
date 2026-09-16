rule Win_Downloader_95109_1
{
strings:
	$a0 = { 696f6e5c52756e2f7205646c6c33322e657865 }


condition:
	$a0
}