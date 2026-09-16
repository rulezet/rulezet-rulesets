rule Win_Downloader_10685_1
{
strings:
	$a0 = { 8d05a002400083c004ffd06a00e800000000ff2530024000 }


condition:
	$a0
}