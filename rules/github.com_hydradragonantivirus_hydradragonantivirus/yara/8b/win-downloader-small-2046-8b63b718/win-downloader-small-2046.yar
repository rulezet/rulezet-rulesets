rule Win_Downloader_Small_2046
{
strings:
	$a0 = { 46d86874e270383a2ffa0c796d616e3c63722e796ffc69f867e875fbbc6c }


condition:
	$a0
}