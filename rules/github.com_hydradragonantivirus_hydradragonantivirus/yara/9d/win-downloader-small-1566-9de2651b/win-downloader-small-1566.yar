rule Win_Downloader_Small_1566
{
strings:
	$a0 = { ff75088d85fcfeffff6a00684860001050ff15ec500010ff75088d9e10010000bf246000108bcb57e83d2f0000 }


condition:
	$a0
}