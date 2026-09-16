rule Win_Downloader_Small_2602
{
strings:
	$a0 = { 468e687423703a2f8fa769d76df76ef12e636fdfe94461 }


condition:
	$a0
}