rule Win_Downloader_Small_3496
{
strings:
	$a0 = { bb2f21400081eb10204000b910204000eb04d45f0a02 }


condition:
	$a0
}