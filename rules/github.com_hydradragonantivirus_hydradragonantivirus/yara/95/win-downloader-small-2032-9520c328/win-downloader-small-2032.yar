rule Win_Downloader_Small_2032
{
strings:
	$a0 = { 46ec6871741c703a2f7d6194792e63d56de864617274fe69f1d967b73a2ab172 }


condition:
	$a0
}