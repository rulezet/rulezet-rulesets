rule Win_Downloader_Small_1119
{
strings:
	$a0 = { 776e302e6578650000002f582e657865000034382e646170666565 }


condition:
	$a0
}