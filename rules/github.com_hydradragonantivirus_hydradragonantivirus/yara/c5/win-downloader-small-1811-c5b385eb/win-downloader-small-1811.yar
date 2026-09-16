rule Win_Downloader_Small_1811
{
strings:
	$a0 = { 68748e703a2f2c77022efe64e46e3b3231d08174ffb1f418785f461120ca6e663d7cf43a3d5c627b3f742e146c6449e0676f }


condition:
	$a0
}