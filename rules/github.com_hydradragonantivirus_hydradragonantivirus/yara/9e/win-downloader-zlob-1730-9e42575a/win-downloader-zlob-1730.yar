rule Win_Downloader_Zlob_1730
{
strings:
	$a0 = { 8d45e8508d85e4feffff5053536858820010ff75f0ff1540800010 }


condition:
	$a0
}