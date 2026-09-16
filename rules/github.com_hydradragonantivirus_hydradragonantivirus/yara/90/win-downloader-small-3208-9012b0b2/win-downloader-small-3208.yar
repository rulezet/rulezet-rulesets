rule Win_Downloader_Small_3208
{
strings:
	$a0 = { c02accbc9ccd9263c23f9427c484cc0d5c1efae7c68a98e8c86a5927c86b9bfcc86a98edb112e273976a82bc2d10e441ac1699e8d86ae6965815e9e8c96a999bba19f0547763 }


condition:
	$a0
}