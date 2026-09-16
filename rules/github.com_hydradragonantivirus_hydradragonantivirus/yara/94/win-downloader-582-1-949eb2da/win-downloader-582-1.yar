rule Win_Downloader_582_1
{
strings:
	$a0 = { b840ae4100e803ffffff84c0742a6a008d45f0e8f9fdffff8d45f0ba6cae4100e8a491feff8b45f0e89493feff50e8aeb0feff }


condition:
	$a0
}