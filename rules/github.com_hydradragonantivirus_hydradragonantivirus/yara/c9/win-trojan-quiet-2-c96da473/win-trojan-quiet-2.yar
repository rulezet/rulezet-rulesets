rule Win_Trojan_Quiet_2
{
strings:
	$a0 = { ba00001e8e1e9c05b43fcd211f7265 }


condition:
	$a0
}