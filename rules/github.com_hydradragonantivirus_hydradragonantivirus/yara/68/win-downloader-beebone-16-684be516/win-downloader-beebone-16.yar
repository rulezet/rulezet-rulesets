rule Win_Downloader_Beebone_16
{
strings:
	$a0 = { 3030307d5c3157656c6c7961726400520000000000000c35232a8f4e0748b26940ec92ad8965da6ec8bc74bb2c45 }


condition:
	$a0
}