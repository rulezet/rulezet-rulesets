rule Win_Downloader_Small_1509
{
strings:
	$a0 = { b90f000000be3c0240008d7dbcf3a5 }


condition:
	$a0
}