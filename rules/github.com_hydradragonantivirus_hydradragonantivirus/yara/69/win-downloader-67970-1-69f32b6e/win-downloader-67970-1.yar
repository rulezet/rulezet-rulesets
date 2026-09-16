rule Win_Downloader_67970_1
{
strings:
	$a0 = { 55545d83ec248d45dc50ff1508303e00e801 }


condition:
	$a0
}