rule Win_Downloader_Delf_806
{
strings:
	$a0 = { 6a006a006890814000a1b0a84000e82ab9ffff506a00e8a6fdffff6a056890814000e846c5ffff33c05a595964891068c0804000 }


condition:
	$a0
}