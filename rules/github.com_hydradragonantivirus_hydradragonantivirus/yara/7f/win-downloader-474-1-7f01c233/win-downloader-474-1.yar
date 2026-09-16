rule Win_Downloader_474_1
{
strings:
	$a0 = { 558bec83c4f0b818364000e83cfdffff33c05568e136400064ff30648920e8b9eeffff6a0168f0364000e8d1fdffff }


condition:
	$a0
}