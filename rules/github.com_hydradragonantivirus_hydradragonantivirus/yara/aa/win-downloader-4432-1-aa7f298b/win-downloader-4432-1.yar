rule Win_Downloader_4432_1
{
strings:
	$a0 = { 648920e800001538b870564000bae0364000e800001f90 }


condition:
	$a0
}