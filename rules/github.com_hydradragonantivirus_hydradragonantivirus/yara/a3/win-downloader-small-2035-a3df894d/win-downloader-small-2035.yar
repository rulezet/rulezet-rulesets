rule Win_Downloader_Small_2035
{
strings:
	$a0 = { 46b16874c4703a712f75753164613a2e6db33430739366 }


condition:
	$a0
}