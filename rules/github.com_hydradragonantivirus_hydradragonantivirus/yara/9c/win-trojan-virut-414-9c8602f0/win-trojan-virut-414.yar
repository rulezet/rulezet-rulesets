rule Win_Trojan_Virut_414
{
strings:
	$a0 = { 83ec306083c4247100e876feffff035c24fc2adb83eb3c83eb440fb793bc1c000081d22beeffff }


condition:
	$a0
}