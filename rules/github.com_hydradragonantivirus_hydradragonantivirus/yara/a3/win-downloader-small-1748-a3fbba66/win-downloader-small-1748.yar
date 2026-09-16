rule Win_Downloader_Small_1748
{
strings:
	$a0 = { 40006a00e8450100008945fc6a016a006a008d7df3576a006a00e83b0100006a006a008d7dea57 }


condition:
	$a0
}