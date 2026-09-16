rule Win_Downloader_2143_1
{
strings:
	$a0 = { e80ffcffff84c074ed8d45f0ba384f4000e81aedffff8d45f0e882efffffc6400c6b8d45f0e876efffff }


condition:
	$a0
}