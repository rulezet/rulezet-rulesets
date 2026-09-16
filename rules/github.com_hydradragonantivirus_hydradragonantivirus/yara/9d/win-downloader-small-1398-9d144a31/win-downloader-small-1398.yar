rule Win_Downloader_Small_1398
{
strings:
	$a0 = { 6100660066006d006f00640065006c0073002e0063006f006d0000000000ffffff }


condition:
	$a0
}