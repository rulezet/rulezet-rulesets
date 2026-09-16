rule Win_Downloader_Small_1726
{
strings:
	$a0 = { 5058be6d30400046464666890658464624ff50e899020000 }


condition:
	$a0
}