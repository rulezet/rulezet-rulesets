rule Win_Downloader_Small_1673
{
strings:
	$a0 = { f2ae8bcb4fc1e902f3a58bcb8d84240c06000083e10350f3a468e0824000eb3b }


condition:
	$a0
}