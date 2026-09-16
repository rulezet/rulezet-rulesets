rule Win_Downloader_Small_1501
{
strings:
	$a0 = { e8b4fcffff8b15a4401413a1a0401413e860ffffff84c0741d }


condition:
	$a0
}