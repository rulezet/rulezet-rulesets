rule Win_Downloader_Small_1427
{
strings:
	$a0 = { 6878391413e8befcffff6884391413e8b4fcffff8b15a4401413a1a0401413e860ffffff84c0741e906a016a006a00a1a4401413e8aff7ffff5068903914136a00e88afdffff }


condition:
	$a0
}