rule Win_Downloader_Banload_840
{
strings:
	$a0 = { 6c7b366f716e0000ffffffff0b0000005c78736d6974682e73637200ffffffff090000005c736d73632e6578 }


condition:
	$a0
}