rule Win_Downloader_W32_70
{
strings:
	$a0 = { 1040008985ecfeffff6a026a006afc8b95ecfeffff52ff15181040006a008d45fc506a048d8df0feffff518b95ecfeffff52ff151410400081bdf0feffff0df0000074076a00e8b50300006a026a0068 }


condition:
	$a0
}