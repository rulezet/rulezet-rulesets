rule Win_Downloader_Swizzor_285
{
strings:
	$a0 = { f98ba12bb938b5d2aefb05c281da3416ecfec8d4909eec6228aa83cbdd1e7e8bd815c1c74b81f5c3027c62a13cb82724 }


condition:
	$a0
}