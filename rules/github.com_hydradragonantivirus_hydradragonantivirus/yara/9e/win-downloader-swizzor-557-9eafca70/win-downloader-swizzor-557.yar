rule Win_Downloader_Swizzor_557
{
strings:
	$a0 = { f33b20c1eb1cf1b992cb74c309038d96dbfbca4cbab65bf7e7c3d394c2a046fbafa920df0cba00ce4541981d60e69fcf8e20aa5a036af438054f0eb9d8994d318ef49416b5846def4ca28a05 }


condition:
	$a0
}