rule Win_Downloader_Small_1587
{
strings:
	$a0 = { 0fe9d389ffe800000000dde38b14240fdfc487ff4489ed44da24248d094489ff87ed4489ed89c983ea0ad9cbd904240fefd2 }


condition:
	$a0
}