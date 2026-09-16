rule Win_Downloader_Inject_117
{
strings:
	$a0 = { 2f7570646174652f636f756e742e617370[0-3]7e7e616c6c74686573616d65 }


condition:
	$a0
}