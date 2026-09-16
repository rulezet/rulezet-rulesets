rule Win_Downloader_13160_1
{
strings:
	$a0 = { 5068743840006a00e82ffeffff6a018d45e0e8ddfeffff8b45e08d55e4e85afeffff8d45e4ba68384000e825f8ffff8b45e4e8e5f8ffff50e84ffdffff }


condition:
	$a0
}