rule Win_Downloader_Small_1665
{
strings:
	$a0 = { 8d4de8ba042b4000b8182b4000e867f7ffff8b45e88b158c474000e849f3ffff48a3a04740008bc633d25250a1a0474000 }


condition:
	$a0
}