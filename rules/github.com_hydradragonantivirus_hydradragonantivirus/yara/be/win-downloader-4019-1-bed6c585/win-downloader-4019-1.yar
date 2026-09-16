rule Win_Downloader_4019_1
{
strings:
	$a0 = { 76d0d96d0bdde3796f44785523e9bec96c6e4281d641ffb97039fdc53aa45df8935d9779809ce0d9aa83f714db6d722b879a88042f33b41e7abd74d619cb998a }


condition:
	$a0
}