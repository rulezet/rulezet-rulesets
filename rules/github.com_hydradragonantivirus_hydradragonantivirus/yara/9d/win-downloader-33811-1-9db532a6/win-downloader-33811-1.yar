rule Win_Downloader_33811_1
{
strings:
	$a0 = { 558bec81ec44020000[0-90]83f8??7e0? }


condition:
	$a0
}