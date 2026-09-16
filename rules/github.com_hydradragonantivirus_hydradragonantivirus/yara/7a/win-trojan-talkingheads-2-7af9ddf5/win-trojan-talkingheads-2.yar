rule Win_Trojan_TalkingHeads_2
{
strings:
	$a0 = { 3ecd21b404b001b500b101b600b200cd137237b45bb920 }


condition:
	$a0
}