rule Win_Downloader_Small_935
{
strings:
	$a0 = { 75752e7500000000ffffffff2f000000ccd8d8d49e9393dbdbdb92d0d3c5c8c7c5d7cc92c6cdde93c5c8dac9d6d8d793d7d8c5d8d793999993d9c792d4ccd400ffffffff15000000697a78787a6473616673 }


condition:
	$a0
}