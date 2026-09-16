rule Win_Downloader_223_1
{
strings:
	$a0 = { 17e41a2f0345b7f01d21e726878fbec82cd1b273ec55353f8059c10edb1cf3a60eec13bd927794ee2fe00449c0d28537c825993dd96cd32ce2a4bf2b297f1b316a1fb65f5ed3a1d0c254a2af9be2af0e9cdcf30c3a }


condition:
	$a0
}