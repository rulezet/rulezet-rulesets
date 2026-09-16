rule Win_Downloader_Istbar_60
{
strings:
	$a0 = { 42425697f0ffdb6d49535f7762075c69696e7374616c6c2e657865ffbffd4d917474703a2f2f77002e736c6f7463 }


condition:
	$a0
}