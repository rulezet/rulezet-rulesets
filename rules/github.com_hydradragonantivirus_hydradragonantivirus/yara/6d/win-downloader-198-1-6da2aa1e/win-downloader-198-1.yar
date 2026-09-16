rule Win_Downloader_198_1
{
strings:
	$a0 = { 24180c34cdb26900f810f4ece4d3344dd3dcd8d0ccc400de344dbcb4ac4a61636b87c00ae8a04bb5ae657dffe6df6e6e1e4a756c69614e656f00416c616e364a4a3d029e9d1e4f194761 }


condition:
	$a0
}