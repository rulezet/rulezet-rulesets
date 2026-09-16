rule Win_Downloader_11320_1
{
strings:
	$a0 = { 68dc324000e8bef6ffff6a006a006a036a006a0068000000806849354000e897010000 }


condition:
	$a0
}