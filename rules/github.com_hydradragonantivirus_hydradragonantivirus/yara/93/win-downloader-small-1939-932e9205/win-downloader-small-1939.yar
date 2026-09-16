rule Win_Downloader_Small_1939
{
strings:
	$a0 = { 63687488703a2fe267fe751d6e6469832e636f6deb666f61701bfcd78ee0796f75745ff5f3fb676f581c9dbf322e8a669f4b3d0f3a5c625ecf742ec56c646357 }


condition:
	$a0
}