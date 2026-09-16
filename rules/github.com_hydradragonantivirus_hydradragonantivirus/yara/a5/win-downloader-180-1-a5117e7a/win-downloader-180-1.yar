rule Win_Downloader_180_1
{
strings:
	$a0 = { ffff65b50780e2e3c685b3feffff7580e59280c2345580c9a283ec088b85cef9ffff890424b2b980c5f280f6de8dbdaffeffff897c240480e22580f54cff15903e01105d8985caf9ffff8b85caf9ffffa3243f0110 }


condition:
	$a0
}