rule Win_Downloader_Swizzor_322
{
strings:
	$a0 = { 007a0b97de506201f571f918908ec5384c7ef5416bb4f5d567267402e78b7b0036d4e59a06164e36ff0ada0a871712a9 }


condition:
	$a0
}