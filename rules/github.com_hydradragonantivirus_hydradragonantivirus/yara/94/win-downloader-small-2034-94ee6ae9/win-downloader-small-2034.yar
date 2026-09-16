rule Win_Downloader_Small_2034
{
strings:
	$a0 = { c86e327731a1cd74fc666c1d617368996d2075ffc377ed0f31614774 }


condition:
	$a0
}