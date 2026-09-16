rule Win_Downloader_Swizzor_272
{
strings:
	$a0 = { 06b92a595029b7a08648356848c04fc5af1ee51209f8d53743eb0ab8236b4dc57cd7525d9afc48ae9ced9b76170384c9 }


condition:
	$a0
}