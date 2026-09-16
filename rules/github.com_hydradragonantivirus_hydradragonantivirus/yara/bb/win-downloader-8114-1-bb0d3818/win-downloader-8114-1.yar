rule Win_Downloader_8114_1
{
strings:
	$a0 = { 558bec83c4ec5356578d75fc90eb01e8908b442414250000ffff81384d5a900074072d00100000ebf1 }


condition:
	$a0
}