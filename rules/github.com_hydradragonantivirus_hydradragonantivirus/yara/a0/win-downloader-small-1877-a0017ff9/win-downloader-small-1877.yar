rule Win_Downloader_Small_1877
{
strings:
	$a0 = { bf5c204000bef4214000b34f }


condition:
	$a0
}