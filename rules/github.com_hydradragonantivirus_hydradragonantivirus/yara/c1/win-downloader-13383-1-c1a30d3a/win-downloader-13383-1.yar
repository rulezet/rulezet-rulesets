rule Win_Downloader_13383_1
{
strings:
	$a0 = { 6a005b682c434000e845f3ffff6a006a006a036a006a006800000080684c434000e8 }


condition:
	$a0
}