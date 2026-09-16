rule Win_Downloader_Swizzor_480
{
strings:
	$a0 = { 9dba8f4031dc3a71fc4b0369812d6ffba6898af1ce14d71ac16b892cd5063b43a5f8afa9ccc20b612d06c8e3a953bbe92cdaba23698089e8920a7bad428554f8e5d8fd4d4e2b368899af6218272c }


condition:
	$a0
}