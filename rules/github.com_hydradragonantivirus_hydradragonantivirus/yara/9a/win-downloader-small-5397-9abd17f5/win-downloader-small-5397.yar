rule Win_Downloader_Small_5397
{
strings:
	$a0 = { a5a5a56a0abecc104000598d7d94f3a566a56a09bea41040 }


condition:
	$a0
}