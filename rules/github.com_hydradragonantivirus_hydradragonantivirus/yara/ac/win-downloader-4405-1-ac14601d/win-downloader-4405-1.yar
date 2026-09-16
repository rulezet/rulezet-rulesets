rule Win_Downloader_4405_1
{
strings:
	$a0 = { 8b3d1420400083c41056ffd7e88cfcffff50ff74242889442420685421400056ffd383c41056ffd7e821faffff }


condition:
	$a0
}