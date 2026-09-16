rule Win_Downloader_Delf_1697
{
strings:
	$a0 = { 221618f2eebf636d7273732e6578650b6d736263ffffefbe4f2507786c6c70a6b1b1737f6e777f72b27f746a7b6db219ecffee }


condition:
	$a0
}