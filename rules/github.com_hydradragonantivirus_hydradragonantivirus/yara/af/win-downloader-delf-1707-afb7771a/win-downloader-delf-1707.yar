rule Win_Downloader_Delf_1707
{
strings:
	$a0 = { e85efaffff5068b83515146a00e841ffffff }


condition:
	$a0
}