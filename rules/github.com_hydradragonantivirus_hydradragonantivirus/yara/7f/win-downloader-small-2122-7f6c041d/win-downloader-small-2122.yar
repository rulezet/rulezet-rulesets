rule Win_Downloader_Small_2122
{
strings:
	$a0 = { 61696c6f727bfbffb61d720872696a75616e612e63612f690d6765731c3edcb17d6f64 }


condition:
	$a0
}