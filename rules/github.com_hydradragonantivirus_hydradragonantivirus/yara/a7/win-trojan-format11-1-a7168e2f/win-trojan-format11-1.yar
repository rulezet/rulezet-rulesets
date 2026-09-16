rule Win_Trojan_Format11_1
{
strings:
	$a0 = { b400b280cd13bb03018cc88ec0b405b280b600b500b101b011cd13b8004ccd21 }


condition:
	$a0
}