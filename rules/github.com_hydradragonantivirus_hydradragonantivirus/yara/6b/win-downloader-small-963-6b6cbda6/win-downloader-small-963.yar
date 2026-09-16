rule Win_Downloader_Small_963
{
strings:
	$a0 = { 6865722e636f6d7c2f696e666f7c496e666f726d6174696f6e205570646174657c69752e6578 }


condition:
	$a0
}