rule Win_Downloader_Istbar_221
{
strings:
	$a0 = { 41717459477161377455002f6169643a31eecbffff303031383530202f6366673a7973625f6c }


condition:
	$a0
}