rule Win_Downloader_Small_1970
{
strings:
	$a0 = { 8b45ec508d45e88b15a0404000e896f8ffff }


condition:
	$a0
}