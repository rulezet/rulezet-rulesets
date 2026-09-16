rule Win_Downloader_Small_3187
{
strings:
	$a0 = { f3ab8d8560feffff688410400050e8e300000083c4108d45f450ff15101040008bf833f63bfe0f84c1000000 }


condition:
	$a0
}