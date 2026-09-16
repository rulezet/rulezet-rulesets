rule Win_Downloader_Small_5138
{
strings:
	$a0 = { 83bd6cfdffff0274348b4d0851686c3100108d9578feffff52e87e01000083c40c688c3100108d8578feffff50e802f9ffff83c4086a00ff1520300010 }


condition:
	$a0
}