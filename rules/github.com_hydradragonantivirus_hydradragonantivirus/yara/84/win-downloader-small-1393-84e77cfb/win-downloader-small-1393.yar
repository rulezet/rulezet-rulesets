rule Win_Downloader_Small_1393
{
strings:
	$a0 = { ea0a266a355553fa303dcd01f6655767611e4b54790f14c909aa }


condition:
	$a0
}