rule Win_Downloader_749_1
{
strings:
	$a0 = { bfcb5cccf881c73565890789fe8d9fd01afe0481eb5416fe0453ff15f8c655000500e023bf290731c08d7f0183c7024739df7ee5ffe6 }


condition:
	$a0
}