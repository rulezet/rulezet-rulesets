rule Win_Downloader_Small_906
{
strings:
	$a0 = { 32d6b14332d6b14332d6b14332d6b1436a006a006800314000 }


condition:
	$a0
}