rule Win_Downloader_Small_3292
{
strings:
	$a0 = { 558bec83ec0c535657ba9810400052e813fcffff }


condition:
	$a0
}