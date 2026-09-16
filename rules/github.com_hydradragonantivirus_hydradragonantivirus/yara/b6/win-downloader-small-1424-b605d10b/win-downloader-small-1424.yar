rule Win_Downloader_Small_1424
{
strings:
	$a0 = { 50ff75088d85f4f6ffffff7704680c63001050ffd68d85f4faffff508d85f4f6ffff50e8befbffff8d85f4faffff5068046300108d85f4f2ffff68dc62001050ffd683c42c895d08 }


condition:
	$a0
}