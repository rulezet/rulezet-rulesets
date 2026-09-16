rule Win_Downloader_Small_2124
{
strings:
	$a0 = { 558bec81ec300100008365fc00b81812a02a568945d4c745d8fc11a02ac745dcd011a02a }


condition:
	$a0
}