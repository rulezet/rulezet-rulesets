rule Win_Downloader_Swizzor_297
{
strings:
	$a0 = { 90a2967e188515d20a174ef3ba1bd1cdeec04c518941eb629def040761a475977c9c09ad94d1ff937bf650ae050a98ba }


condition:
	$a0
}