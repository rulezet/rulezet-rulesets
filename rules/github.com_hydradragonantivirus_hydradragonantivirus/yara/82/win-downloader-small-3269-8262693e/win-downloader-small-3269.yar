rule Win_Downloader_Small_3269
{
strings:
	$a0 = { 8d85ecfdffff68a820400050ffd6bf4c2040006a0457e82c020000 }


condition:
	$a0
}