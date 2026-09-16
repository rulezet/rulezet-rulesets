rule Win_Downloader_10798_1
{
strings:
	$a0 = { 558becb9060000006a006a004975f9b8??4a4000e8??f1ffff33c05568??4c400064ff3064892068f4010000e8??f3ffff }


condition:
	$a0
}