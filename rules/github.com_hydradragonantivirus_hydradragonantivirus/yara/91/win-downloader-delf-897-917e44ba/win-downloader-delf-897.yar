rule Win_Downloader_Delf_897
{
strings:
	$a0 = { 6a006a008d45e4b9a08140008b15a4a84000e8a7b9ffff8b45e4e89fbaffff50a1b0a84000e894baffff506a00e848feffff6a05 }


condition:
	$a0
}