rule Win_Downloader_Zlob_2309
{
strings:
	$a0 = { 79a748fd4cce27b90d50a57922584cbea2512805fe21b5b7bfbcd87df84ccbe92988222f96a8ed74a99fa6fe95ab4a2d0cc6c5e07353443bfade988741bb0ff28d5f3e3073d347df6d6a79fdb3d1 }


condition:
	$a0
}