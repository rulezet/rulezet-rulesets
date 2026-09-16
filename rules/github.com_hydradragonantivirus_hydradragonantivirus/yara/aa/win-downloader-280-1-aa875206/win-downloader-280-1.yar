rule Win_Downloader_280_1
{
strings:
	$a0 = { 7d66845de96f5f6f6f6f875f5666aa65e96ccfea5a619c62e96c5aed8160a9ea8261cf5ae96c6f6c6c6c81ee9c95b472725aed873b55619c62e96ccf9b6e9f7252336c9c3cb472729b6ccf9c47b4 }


condition:
	$a0
}