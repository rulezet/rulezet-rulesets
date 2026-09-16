rule Win_Downloader_10513_1
{
strings:
	$a0 = { 9087fb87fb9087d287db87db }


condition:
	$a0
}