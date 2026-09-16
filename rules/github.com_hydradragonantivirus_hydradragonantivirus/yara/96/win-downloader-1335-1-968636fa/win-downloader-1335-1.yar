rule Win_Downloader_1335_1
{
strings:
	$a0 = { e80200000050c35589e581ec0c020000c785f4fdffff48757920c785f8fdffff76616d2166c7 }


condition:
	$a0
}