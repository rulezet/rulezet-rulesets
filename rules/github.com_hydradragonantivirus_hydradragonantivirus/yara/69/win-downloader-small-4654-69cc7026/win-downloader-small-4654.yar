rule Win_Downloader_Small_4654
{
strings:
	$a0 = { ff2500204000ff250c204000cccc558bec81c47cfeffff5657e8e2ffffff8945fc33c98b75fcac3c007407 }


condition:
	$a0
}