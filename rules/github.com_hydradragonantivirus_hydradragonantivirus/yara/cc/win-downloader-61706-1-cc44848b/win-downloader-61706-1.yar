rule Win_Downloader_61706_1
{
strings:
	$a0 = { 535b60b86be90000505b39d87d039090f4610f31b900cc4000516660558bec83 }

	$a1 = { 8945f05350585b }


condition:
	$a0 and $a1
}