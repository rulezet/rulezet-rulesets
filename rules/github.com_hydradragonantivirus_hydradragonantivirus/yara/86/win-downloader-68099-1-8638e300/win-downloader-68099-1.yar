rule Win_Downloader_68099_1
{
strings:
	$a0 = { 837c2408017505e80500bca2ff7424048b4c2410 }


condition:
	$a0
}