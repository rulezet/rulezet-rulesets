rule Win_Trojan_Parasite_12
{
strings:
	$a0 = { 83fb0072915933c033db33d233f6bf00015733ffc2ffff }


condition:
	$a0
}