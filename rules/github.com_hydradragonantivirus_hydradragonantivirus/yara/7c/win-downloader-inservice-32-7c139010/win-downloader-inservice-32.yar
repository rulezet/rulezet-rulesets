rule Win_Downloader_INService_32
{
strings:
	$a0 = { 73093130300d0a6409746f64617909667265652d726164696f2e62 }


condition:
	$a0
}