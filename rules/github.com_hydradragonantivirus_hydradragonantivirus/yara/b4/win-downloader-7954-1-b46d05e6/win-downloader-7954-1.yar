rule Win_Downloader_7954_1
{
strings:
	$a0 = { 684b404000e800000000586061eb005850e80000000083c40433c7c3 }


condition:
	$a0
}