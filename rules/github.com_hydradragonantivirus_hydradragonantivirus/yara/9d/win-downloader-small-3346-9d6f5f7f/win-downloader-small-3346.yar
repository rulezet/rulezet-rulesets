rule Win_Downloader_Small_3346
{
strings:
	$a0 = { 6a0abe94304000598d7dc4f3a5be843040008d7deca5a5a5 }


condition:
	$a0
}