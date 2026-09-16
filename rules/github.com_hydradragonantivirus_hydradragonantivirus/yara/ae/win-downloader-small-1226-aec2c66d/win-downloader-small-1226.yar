rule Win_Downloader_Small_1226
{
strings:
	$a0 = { 696c65410075726c6d6f6e2e646c6c006162797276616c67000000 }


condition:
	$a0
}