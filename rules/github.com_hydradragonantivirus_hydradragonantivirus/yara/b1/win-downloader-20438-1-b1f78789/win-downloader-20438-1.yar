rule Win_Downloader_20438_1
{
strings:
	$a0 = { 5c6b72362e74787400000000687474703a2f2f }


condition:
	$a0
}