rule Win_Downloader_Monurl_7
{
strings:
	$a0 = { 6c6c002e006d6f6e0075726c00410046696c6500546f00446f776e6c6f61640055524c00 }


condition:
	$a0
}