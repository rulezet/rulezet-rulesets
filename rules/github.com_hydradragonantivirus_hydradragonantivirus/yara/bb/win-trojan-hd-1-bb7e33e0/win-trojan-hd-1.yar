rule Win_Trojan_HD_1
{
strings:
	$a0 = { 05b202b600b500b101b008cd13b400cd21 }


condition:
	$a0
}