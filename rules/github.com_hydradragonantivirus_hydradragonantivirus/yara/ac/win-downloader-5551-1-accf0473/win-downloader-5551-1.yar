rule Win_Downloader_5551_1
{
strings:
	$a0 = { 6e9b792e636f6d2f5643442f308025c2ce0077810d3c4853 }


condition:
	$a0
}