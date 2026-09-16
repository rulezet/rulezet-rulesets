rule Win_Trojan_Mybot_5527
{
strings:
	$a0 = { 0e475a913ac7dfaa2a6db49493d1b24d1f6c8d273762b1b691684379df5447c111f8448bee57fe1dab20778b41a39b713f8985120697d2088e0bc0ff1aecb5d5dbffa0cf8368 }


condition:
	$a0
}