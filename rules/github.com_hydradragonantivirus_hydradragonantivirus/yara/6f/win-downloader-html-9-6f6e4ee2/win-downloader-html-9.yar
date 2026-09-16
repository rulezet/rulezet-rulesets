rule Win_Downloader_HTML_9
{
strings:
	$a0 = { 636f6465626173653d22[0-15]2e657865223e3c2f6f626a6563743e3c2f626f64793e }


condition:
	$a0
}