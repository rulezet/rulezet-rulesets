rule Win_Downloader_VB_405
{
strings:
	$a0 = { b5ba0d1f174f08429d0476a64ac80b90cb4badadb17a86ad1fc6811bc674940f722035e7217ebd400be1134109897e0733351fce9ec8ee5bd3f66fcf4af56a1cfe }


condition:
	$a0
}