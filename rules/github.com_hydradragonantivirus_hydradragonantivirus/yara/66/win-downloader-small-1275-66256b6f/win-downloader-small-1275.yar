rule Win_Downloader_Small_1275
{
strings:
	$a0 = { 6a006a00687115400068041040006a00e8580000000bc07517 }


condition:
	$a0
}