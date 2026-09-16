rule Win_Downloader_Small_1560
{
strings:
	$a0 = { 31c00fefe40fd524240f6f1c240fe9dc0f7f1c248b042485c074e531c0 }


condition:
	$a0
}