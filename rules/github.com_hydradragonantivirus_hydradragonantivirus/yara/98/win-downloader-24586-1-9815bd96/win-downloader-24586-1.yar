rule Win_Downloader_24586_1
{
strings:
	$a0 = { 53??34120000[0-1]5783c7046633fb4f5281ef23100000??89070000 }


condition:
	$a0
}