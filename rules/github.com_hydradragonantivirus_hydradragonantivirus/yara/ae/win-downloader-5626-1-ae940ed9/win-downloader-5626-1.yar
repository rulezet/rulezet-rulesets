rule Win_Downloader_5626_1
{
strings:
	$a0 = { 558bec83c4f0b8d87e4000e8ecc4ffff33d2b8c07f4000e8d0feffffbae07f4000b800804000e821feffff }


condition:
	$a0
}