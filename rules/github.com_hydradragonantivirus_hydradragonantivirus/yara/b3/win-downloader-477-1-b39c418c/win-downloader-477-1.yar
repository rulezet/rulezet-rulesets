rule Win_Downloader_477_1
{
strings:
	$a0 = { 3c47fe388d7fa74e8219a2e4185c3816ac78efff208bf1ad237790c96abeb49e18855af8e14e5e11a7b5758f8e955e7fd54e4cd4793c77df60ceb7d2946cce86ccc18e75ef5d70eed2f49689eb1d }


condition:
	$a0
}