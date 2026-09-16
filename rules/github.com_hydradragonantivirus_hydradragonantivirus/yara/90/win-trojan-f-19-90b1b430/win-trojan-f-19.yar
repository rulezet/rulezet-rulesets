rule Win_Trojan_F_19
{
strings:
	$a0 = { 8c0e8600fbc3fab800108ed0bc0000b280b010b101b500b600b4025251cd1359 }


condition:
	$a0
}