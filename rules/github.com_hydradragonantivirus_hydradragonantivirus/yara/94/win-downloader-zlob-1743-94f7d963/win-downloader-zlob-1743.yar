rule Win_Downloader_Zlob_1743
{
strings:
	$a0 = { c76a012e8b2146717dc34a76cb66236aafc507eede5b2a619dfd8159480a14830c0ff3574f990077f09ced1991a3a7d23f3f0df0c1f71c0f7ba1c128161074eed9853d9634a68cef5fcfb74c776c }


condition:
	$a0
}