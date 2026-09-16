rule Win_Downloader_Agent_32603
{
strings:
	$a0 = { e8094dffff6a006a008d45e4b960f540008b15bc434100e88a4fffff8b45e4e88250ffff50a1c8434100e87750ffff506a00e84fbeffff6a058d45e0b960f540008b15bc434100 }


condition:
	$a0
}