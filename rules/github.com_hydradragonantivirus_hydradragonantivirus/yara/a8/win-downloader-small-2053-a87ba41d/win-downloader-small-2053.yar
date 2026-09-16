rule Win_Downloader_Small_2053
{
strings:
	$a0 = { 741c703a2f5d754c64613a2e6c6d343073e466f7eb }


condition:
	$a0
}