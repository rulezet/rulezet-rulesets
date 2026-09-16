rule Win_Downloader_Swizzor_261
{
strings:
	$a0 = { 25f9ea7f3e5c05e835a838fb503d85799354f04b84529de304f268fe1f97aee236ea0c2939544b23e45842704eb7fc8f }


condition:
	$a0
}