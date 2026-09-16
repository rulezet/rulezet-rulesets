rule Win_Downloader_Small_1733
{
strings:
	$a0 = { 87f6bac00a49008d6d0087ff81e20000f0ff0fdfc3d9fe87f681c2001209008d6d000f6fe08cc90fdfc987ed }


condition:
	$a0
}