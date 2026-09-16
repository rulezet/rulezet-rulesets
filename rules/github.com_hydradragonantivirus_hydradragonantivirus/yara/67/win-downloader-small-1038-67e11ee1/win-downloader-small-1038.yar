rule Win_Downloader_Small_1038
{
strings:
	$a0 = { 6c1f73636875747a2e67b7c936bd003277456c64336362fceeb7721c6f702e6e752f676f6675 }


condition:
	$a0
}