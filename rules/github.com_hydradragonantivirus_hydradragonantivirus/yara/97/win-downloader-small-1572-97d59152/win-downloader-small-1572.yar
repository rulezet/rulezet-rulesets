rule Win_Downloader_Small_1572
{
strings:
	$a0 = { b8c41040006a07506a015350ffb5a4fcffffff1530104000 }


condition:
	$a0
}