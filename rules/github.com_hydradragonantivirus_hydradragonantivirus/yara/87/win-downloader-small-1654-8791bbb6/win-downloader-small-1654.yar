rule Win_Downloader_Small_1654
{
strings:
	$a0 = { 87c9ba70e848008d6d000fefcc81e20000f0ffd9e087eddde381c200f208000fdfc98cc90fd5d49bdbe387ff30c9 }


condition:
	$a0
}