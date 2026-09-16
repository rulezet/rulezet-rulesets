rule Win_Downloader_W32_15
{
strings:
	$a0 = { 5346581def6d9b39ac1c1a4c7e6b563127dffd5dfb6e6f6272610dd56269652e636f6df7746f6f7374b09f6d2f69642e }


condition:
	$a0
}