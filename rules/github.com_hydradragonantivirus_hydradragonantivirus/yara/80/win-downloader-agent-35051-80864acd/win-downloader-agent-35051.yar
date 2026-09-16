rule Win_Downloader_Agent_35051
{
strings:
	$a0 = { cf093c4b754ce1d1ae77069a8d59904ecf33dfd43834f5a58738e98c5ba24d3fdc02d8c38a067d9dcfc410420652f76ecf86 }


condition:
	$a0
}