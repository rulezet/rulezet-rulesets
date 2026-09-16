rule Win_Downloader_Small_4908
{
strings:
	$a0 = { 558bec6a0168a8204000e859fcffff83c4086a0168d4204000e84afcffff }


condition:
	$a0
}