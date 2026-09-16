rule Win_Trojan_Emperor_2
{
strings:
	$a0 = { 450303c38945125007571f832e13041a0e1fe800005e81ee1101b97118fcf3a506b88b0150cb }


condition:
	$a0
}