rule Win_Downloader_Small_3305
{
strings:
	$a0 = { ded73b4d9ba91416b8b443ee68b04b8bda70a6f4c3a3068489a673217e6527113997b42234e4374d8ccb63d57efa852d14fe27d542e9694498a2 }


condition:
	$a0
}