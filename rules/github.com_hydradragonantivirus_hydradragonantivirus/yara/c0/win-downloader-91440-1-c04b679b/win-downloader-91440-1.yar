rule Win_Downloader_91440_1
{
strings:
	$a0 = { f291f87301f6eb02cd20f97201d3f873011af97201a3eb02cd20f20bcaeb013a }


condition:
	$a0
}