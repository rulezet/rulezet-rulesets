rule Win_Downloader_Delf_958
{
strings:
	$a0 = { 6a006a004975f95153b894c64400e83193fbff33c055683fcb440064ff30648920684ccb44006a00e88fa0fbff }


condition:
	$a0
}