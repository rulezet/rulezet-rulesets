rule Win_Downloader_Small_1630
{
strings:
	$a0 = { 226332752e62690e5c6c73efe5dffe6173732e65786513433a5c }


condition:
	$a0
}