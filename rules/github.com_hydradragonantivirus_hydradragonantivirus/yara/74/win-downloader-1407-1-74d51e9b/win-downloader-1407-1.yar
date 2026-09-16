rule Win_Downloader_1407_1
{
strings:
	$a0 = { 558bec83c4f0b80c7e4000e8b0c5ffff[0-70]75216a006a0068??7f400068??7f40006a00e887c7ffff6a0068??7f4000e89bc6 }


condition:
	$a0
}