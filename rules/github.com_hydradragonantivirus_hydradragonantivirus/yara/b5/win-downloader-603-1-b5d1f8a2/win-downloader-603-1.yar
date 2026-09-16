rule Win_Downloader_603_1
{
strings:
	$a0 = { 8b55f4b8e0684100e803ffffff84c0742a6a008d45f0e8f9fdffff8d45f0ba08694100e87cd6feff8b45f0e86cd8feff50e836f2feff }


condition:
	$a0
}