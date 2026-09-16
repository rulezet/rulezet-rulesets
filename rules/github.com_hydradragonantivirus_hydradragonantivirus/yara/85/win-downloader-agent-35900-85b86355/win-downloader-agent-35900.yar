rule Win_Downloader_Agent_35900
{
strings:
	$a0 = { 558bec83ec108b450c8945f0837df0017402eb418b4d0851ff15c07000106a08 }


condition:
	$a0
}