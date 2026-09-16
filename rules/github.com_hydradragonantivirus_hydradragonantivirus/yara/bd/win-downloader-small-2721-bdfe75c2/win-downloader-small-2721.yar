rule Win_Downloader_Small_2721
{
strings:
	$a0 = { 8d8554f3ffff68f034400050e8e10200008d8590f3ffff682830400050e8d00200008d85f0feffff508d8590f7ffff50e8bd020000 }


condition:
	$a0
}