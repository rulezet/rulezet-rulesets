rule Win_Downloader_Lookme_2
{
strings:
	$a0 = { 3b626d4c4b3f3f3b483c1c6e076f70656e687474f1ff7ffb703a2f2f77002e6c6f6f6b326d652e636f6d2f6170702f447fff8d6fa32f496e7305 }


condition:
	$a0
}