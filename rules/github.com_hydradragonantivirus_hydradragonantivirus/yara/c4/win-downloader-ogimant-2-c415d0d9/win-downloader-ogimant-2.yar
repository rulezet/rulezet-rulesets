rule Win_Downloader_Ogimant_2
{
strings:
	$a0 = { 68766d6d6d6d3132333031393865716468766d6d6d6d31323330313938 }


condition:
	$a0
}