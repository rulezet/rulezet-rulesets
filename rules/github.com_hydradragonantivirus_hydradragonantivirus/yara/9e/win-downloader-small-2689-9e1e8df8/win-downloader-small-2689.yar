rule Win_Downloader_Small_2689
{
strings:
	$a0 = { be32304000bf28324000e8????????????feffff6a00e818000000ff2534204000ff2530204000 }


condition:
	$a0
}