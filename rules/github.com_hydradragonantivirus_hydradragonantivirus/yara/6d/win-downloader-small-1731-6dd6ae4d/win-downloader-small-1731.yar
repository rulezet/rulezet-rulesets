rule Win_Downloader_Small_1731
{
strings:
	$a0 = { 89d2680000400087db0febdb87f6590f6fc80fd5e031d20fe9d8d9f8 }


condition:
	$a0
}