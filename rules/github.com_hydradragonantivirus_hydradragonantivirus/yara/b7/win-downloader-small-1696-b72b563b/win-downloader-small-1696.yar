rule Win_Downloader_Small_1696
{
strings:
	$a0 = { 6a006a0053689c5240006a00e8f3faffff }


condition:
	$a0
}