rule Win_Downloader_Swizzor_296
{
strings:
	$a0 = { a4363a3efc0dc41a61353edcb382ba42e3bfb9a7683d7e7cacb145cad0b0caee491f8f3d41ac394713e0e9ddc92feb65 }


condition:
	$a0
}