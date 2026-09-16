rule Win_Downloader_Small_692
{
strings:
	$a0 = { bc8f2efdc2b30b997a2f0a312e0e703f71713d589b10a829e34efdd84e071cf4496e66971a3f49c84083f91fb72c44a0652f482941b51def6a6b0553707977 }


condition:
	$a0
}