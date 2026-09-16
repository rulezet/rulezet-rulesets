rule Win_Downloader_Lookme_1
{
strings:
	$a0 = { 1267bf6603dcc8c3f2844dbaa6663b626d4c4b3f3f3b483c1c6e076f70656e687474ffff7ffb703a2f2f77002e6c6f6f6b326d652e636f6d2f6170702f424d }


condition:
	$a0
}