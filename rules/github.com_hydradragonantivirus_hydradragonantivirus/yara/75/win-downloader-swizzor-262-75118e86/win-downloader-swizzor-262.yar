rule Win_Downloader_Swizzor_262
{
strings:
	$a0 = { 0a1f5be3afcd4f38473cf0a5b173302609fb15cb45df2f45c00c2029ae1bf1edd29b3998b0a6dd2868d7a67d8afe5483 }


condition:
	$a0
}