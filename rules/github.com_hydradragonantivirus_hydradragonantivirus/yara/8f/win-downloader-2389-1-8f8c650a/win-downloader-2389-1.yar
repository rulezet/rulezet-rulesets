rule Win_Downloader_2389_1
{
strings:
	$a0 = { 70656e226332752e62690e5c6c73efe5dffe6173732e65786513433a5c67627664646c }


condition:
	$a0
}