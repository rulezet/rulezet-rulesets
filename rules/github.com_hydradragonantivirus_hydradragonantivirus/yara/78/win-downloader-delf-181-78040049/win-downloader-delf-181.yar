rule Win_Downloader_Delf_181
{
strings:
	$a0 = { 6173682e62442f0a7665727cb1edff74732f736f66742f7265730c7649370d32249ddb6c705c5f74 }


condition:
	$a0
}