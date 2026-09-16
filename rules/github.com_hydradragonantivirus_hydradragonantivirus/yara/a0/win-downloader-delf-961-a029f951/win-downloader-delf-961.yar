rule Win_Downloader_Delf_961
{
strings:
	$a0 = { 8b55f4b894434100e803ffffff84c0742a6a008d45f0e8f9fdffff8d45f0bac0434100e8c0f9feff8b45f0e8b0fbfeff50e86215ffff }


condition:
	$a0
}