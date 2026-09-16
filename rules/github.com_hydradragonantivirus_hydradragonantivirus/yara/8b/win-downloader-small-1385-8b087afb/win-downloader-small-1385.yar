rule Win_Downloader_Small_1385
{
strings:
	$a0 = { 3377683b636f7f1f726567f9ba78f087c077696e630e686f73741100534f }


condition:
	$a0
}