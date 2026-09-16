rule Win_Downloader_Centim_1
{
strings:
	$a0 = { 6976657c617263686976652e6578657c3232383732 }


condition:
	$a0
}