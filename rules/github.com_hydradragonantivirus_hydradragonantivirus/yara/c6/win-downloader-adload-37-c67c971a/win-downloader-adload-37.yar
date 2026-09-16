rule Win_Downloader_Adload_37
{
strings:
	$a0 = { c745fc05000000c7852cfdffff842d4000c78524fdffff080000008d85d4feffff50 }


condition:
	$a0
}