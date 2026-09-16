rule Win_Downloader_Banload_603
{
strings:
	$a0 = { 73bf42d1cb084da7a4d0662f487304f6b65728be6aac17ae9585c040d9d04b7618cda05821509c3f3003b67f727061f46266b5a2b265bc53b40ce7ccb27f4cdb1bc2d935 }


condition:
	$a0
}