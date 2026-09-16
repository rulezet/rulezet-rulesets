rule Win_Downloader_Small_5127
{
strings:
	$a0 = { 696874747000203a2f2f31323334353637383930080a392e0000636f6d2f78786d }


condition:
	$a0
}