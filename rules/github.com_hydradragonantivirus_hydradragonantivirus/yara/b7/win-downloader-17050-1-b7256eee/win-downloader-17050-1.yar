rule Win_Downloader_17050_1
{
strings:
	$a0 = { e88ffeffff6837304000e809fdffff0bc0740c6a0168e53f4000e85500000050e819000000cc }


condition:
	$a0
}