rule Win_Trojan_Parasite_13
{
strings:
	$a0 = { 240083fb0072915933c033db33d233f6bf00015733ffc2ffff }


condition:
	$a0
}