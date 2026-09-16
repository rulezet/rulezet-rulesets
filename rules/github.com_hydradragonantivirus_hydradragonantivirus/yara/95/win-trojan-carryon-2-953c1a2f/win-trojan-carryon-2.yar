rule Win_Trojan_CarryOn_2
{
strings:
	$a0 = { bf1d032e033e0101b97f00fcf3a4b405bd07032e032e01013a66007444fe4600b42acd2181fa16097345b44e33 }


condition:
	$a0
}