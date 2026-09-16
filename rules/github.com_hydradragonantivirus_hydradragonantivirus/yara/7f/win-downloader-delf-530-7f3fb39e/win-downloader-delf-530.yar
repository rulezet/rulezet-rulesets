rule Win_Downloader_Delf_530
{
strings:
	$a0 = { 558bec6a006a0068bc1f141368e01f14136a00e8a8ffffff6a056834201413e8d4feffff33c0 }


condition:
	$a0
}