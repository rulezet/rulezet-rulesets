rule Win_Downloader_2385_1
{
strings:
	$a0 = { 8d85b8fdffff6a02c745c03c000000897dc8c745cc4c4040008945d4897dd8897ddcc745c440000000 }

	$a1 = { 4f70656e00000000 }


condition:
	$a0 and $a1
}