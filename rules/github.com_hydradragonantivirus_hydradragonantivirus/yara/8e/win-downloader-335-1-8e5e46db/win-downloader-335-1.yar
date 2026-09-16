rule Win_Downloader_335_1
{
strings:
	$a0 = { cc2a07a6b59fc8231c9ef19792f739adb611e984c35cdcf36961eae2507f85fd8c0b2baf239cad1cb03688c584238a3223fdb063275c540d4b7402ef8834efe5fa9886efa9c4dce15a45fe4a3b92db9a9181 }


condition:
	$a0
}