rule Win_Trojan_WMLog_1
{
strings:
	$a0 = { 470403e406c41302032d720909f6ed9b3b4246394e4f4e453bc012101db53120fef6c300 }


condition:
	$a0
}