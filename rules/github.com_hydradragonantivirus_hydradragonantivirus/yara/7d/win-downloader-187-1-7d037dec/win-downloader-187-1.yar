rule Win_Downloader_187_1
{
strings:
	$a0 = { 80c6f1c68573fbffff6580f59780caf7c6856cfbffff67b661c6856ffbffff6f80f6f6c68574fbffff7980f5c380e5d8c68572fbffff4b80e914c68575fbffff0080cd6bc6856bfbffff65c68571fbffff65c6856d }


condition:
	$a0
}