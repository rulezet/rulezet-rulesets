rule Win_Downloader_Dyfuca_10
{
strings:
	$a0 = { baa65936f8e0e4d0c00bb0ff9ba669a89c904459465543415f5349007f4bf29000454e074f505449 }


condition:
	$a0
}