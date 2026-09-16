rule Win_Downloader_82_2
{
strings:
	$a0 = { 6a016a006a006864a64000681cd4400050ff1570a44000c3b8d88d4000e84a5e0000 }


condition:
	$a0
}