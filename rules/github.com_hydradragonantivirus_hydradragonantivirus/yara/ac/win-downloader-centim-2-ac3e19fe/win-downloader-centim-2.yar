rule Win_Downloader_Centim_2
{
strings:
	$a0 = { 5756538dbd00fcffffbe90124000fcb9f3000000f3a566a5 }


condition:
	$a0
}