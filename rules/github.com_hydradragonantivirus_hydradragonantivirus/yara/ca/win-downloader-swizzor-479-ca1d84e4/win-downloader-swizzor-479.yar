rule Win_Downloader_Swizzor_479
{
strings:
	$a0 = { 569f9bc9da1ffe3c630cbf132487cc3ff6227550ecca9c3fd5f4181acca5304e9727167af4bc4fd07d5a4e705f7bd8ff18d9e1bfb8c9f1cebe4d0193422380b7f61a5d82dd54417dbf0ed1c642ea }


condition:
	$a0
}