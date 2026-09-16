rule Win_Downloader_22919_1
{
strings:
	$a0 = { 87d287d29090909087f387f39051535b59bf0f1040009090909087d6 }


condition:
	$a0
}