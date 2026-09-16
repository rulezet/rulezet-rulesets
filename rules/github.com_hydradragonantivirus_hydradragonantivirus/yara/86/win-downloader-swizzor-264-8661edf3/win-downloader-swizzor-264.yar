rule Win_Downloader_Swizzor_264
{
strings:
	$a0 = { c7ec447c20bac167790327d68adcf1f75619eebf04a83e8284997289461a45a30e7c808499feccc68cc6480d0ac8f0f7 }


condition:
	$a0
}