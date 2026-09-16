rule Win_Downloader_Small_2049
{
strings:
	$a0 = { 535657686c134000e8a2feffff8b353010400083c404508d84245c04000050ffd68b3d34104000 }


condition:
	$a0
}