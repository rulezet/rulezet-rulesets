rule Win_Downloader_Small_1272
{
strings:
	$a0 = { 64686c7044656664747c00ff4d300008987474703a2f2f73756349f0ffff63657377 }


condition:
	$a0
}