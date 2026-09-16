rule Win_Downloader_INService_33
{
strings:
	$a0 = { 83c4f88b8534f2ffff506828404000e8c7050000898558f2ffff83c41085c00f8495020000 }


condition:
	$a0
}