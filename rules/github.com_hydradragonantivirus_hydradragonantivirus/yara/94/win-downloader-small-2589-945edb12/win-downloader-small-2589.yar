rule Win_Downloader_Small_2589
{
strings:
	$a0 = { 5580edbc89e581ec9400000081ecfc0c000089e3b2f789254d4f4000a1286040008983e90b0000a12c60400080edcf89 }


condition:
	$a0
}