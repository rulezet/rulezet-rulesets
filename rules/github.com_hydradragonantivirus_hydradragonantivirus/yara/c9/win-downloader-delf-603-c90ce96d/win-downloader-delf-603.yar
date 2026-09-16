rule Win_Downloader_Delf_603
{
strings:
	$a0 = { 53565755bb20664000be00504000bf30604000807b28007516 }


condition:
	$a0
}