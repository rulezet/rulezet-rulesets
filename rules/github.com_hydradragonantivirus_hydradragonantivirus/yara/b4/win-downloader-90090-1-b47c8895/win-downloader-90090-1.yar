rule Win_Downloader_90090_1
{
strings:
	$a0 = { 43003a005c00[0-40]5c004500730077002e006500780065 }


condition:
	$a0
}