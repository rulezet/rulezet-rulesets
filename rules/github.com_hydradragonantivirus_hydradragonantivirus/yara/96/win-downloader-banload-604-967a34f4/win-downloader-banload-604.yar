rule Win_Downloader_Banload_604
{
strings:
	$a0 = { fccb2c2c64044feeaa3dfa5c90699b52643d47adb9e72e2a40080cc3fafc56115abcf43d8ed197978dd41251d25c037e0e5e0bd78be2a298a3ee088d22e257217bcf2057 }


condition:
	$a0
}