rule Win_Downloader_Banload_1054
{
strings:
	$a0 = { 5c776d757061672e657865000000ffffffff28000000687474703a2f2f777777 }


condition:
	$a0
}