rule Win_Downloader_Small_1291
{
strings:
	$a0 = { 71741c703a2f416164696e66ba06fe07792e636f6df075706461f665f7c978 }


condition:
	$a0
}