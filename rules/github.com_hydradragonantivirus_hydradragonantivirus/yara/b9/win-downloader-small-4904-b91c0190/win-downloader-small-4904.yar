rule Win_Downloader_Small_4904
{
strings:
	$a0 = { 6a006a00685c13141368001014136a00e85d0100006a006833101413e82d010000 }


condition:
	$a0
}