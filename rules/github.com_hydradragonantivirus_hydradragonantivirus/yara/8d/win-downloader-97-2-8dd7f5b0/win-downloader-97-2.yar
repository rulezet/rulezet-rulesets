rule Win_Downloader_97_2
{
strings:
	$a0 = { 68f44040008d85acfcffff50ffd68d85b4feffff508d85acfcffff50ffd6ff75108d85acfcffff50e8d62400005f5ec9c3 }


condition:
	$a0
}