rule Win_Trojan_BootKiller_1
{
strings:
	$a0 = { 05b280b600b500b101b008cd13b400cd21 }


condition:
	$a0
}