rule Win_Downloader_Tibs_1
{
strings:
	$a0 = { 90b800a2400031d2d9cb668cca9087ff89db5287ed87db89f6078d1bd80424 }


condition:
	$a0
}