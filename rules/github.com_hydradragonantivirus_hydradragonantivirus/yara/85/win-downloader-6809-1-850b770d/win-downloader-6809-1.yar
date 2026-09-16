rule Win_Downloader_6809_1
{
strings:
	$a0 = { 909087d2565e87f690 }


condition:
	$a0
}