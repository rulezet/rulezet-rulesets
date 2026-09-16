rule Win_Downloader_5624_1
{
strings:
	$a0 = { 8b81948240008038007410eb03 }


condition:
	$a0
}