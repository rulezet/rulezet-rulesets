rule Win_Downloader_Small_4941
{
strings:
	$a0 = { d9cb89dbd9f1683094400000 }


condition:
	$a0
}