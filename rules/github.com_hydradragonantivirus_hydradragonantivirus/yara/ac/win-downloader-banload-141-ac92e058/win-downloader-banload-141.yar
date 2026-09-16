rule Win_Downloader_Banload_141
{
strings:
	$a0 = { e8e0c4ffffb89caa40008b15a4aa4000e8c8bfffff6a058d45ccb9748840008b15aca84000e887b6ffff8b45cce87fb7ffff50e8cdc3ffff }


condition:
	$a0
}