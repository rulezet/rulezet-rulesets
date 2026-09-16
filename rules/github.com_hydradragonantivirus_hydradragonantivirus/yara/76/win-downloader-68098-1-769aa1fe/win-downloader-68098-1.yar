rule Win_Downloader_68098_1
{
strings:
	$a0 = { 558bec6aff689820400068841a400064a10000000050648925 }


condition:
	$a0
}