rule Win_Downloader_Small_2109
{
strings:
	$a0 = { ff15c852400083c404b950864000506878824000e831dcffff84c074338d54240452e813f6ffff }


condition:
	$a0
}