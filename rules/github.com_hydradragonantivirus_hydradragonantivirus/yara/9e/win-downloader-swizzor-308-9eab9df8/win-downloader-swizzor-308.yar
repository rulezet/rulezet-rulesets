rule Win_Downloader_Swizzor_308
{
strings:
	$a0 = { 2f77cd59513ebe05f9b5d81497c7ac560c230d57a0ca08575a5364161f7da81625769de00276f89eea83d56a4b6fddbb }


condition:
	$a0
}