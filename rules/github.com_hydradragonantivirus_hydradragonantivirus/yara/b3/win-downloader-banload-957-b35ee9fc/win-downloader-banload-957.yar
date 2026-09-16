rule Win_Downloader_Banload_957
{
strings:
	$a0 = { 11d0880130c5f3a0610f525be611a26160765e3db14db54395bf67ce68cea656fb2be1fab230a252ec2df18f5b1b33e2a8b1414d8ec70104df460c7a62116c02b4a583d1b4e162ec611fd7aa864e }


condition:
	$a0
}