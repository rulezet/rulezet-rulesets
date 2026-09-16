rule Win_Downloader_Banload_1923
{
strings:
	$a0 = { 558bec83c4f0b8e0d94000e8a073ffffba8cda4000 }


condition:
	$a0
}