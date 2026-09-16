rule Win_Trojan_BadTrack_1
{
strings:
	$a0 = { d88ec0b80106b500b600cd13 }


condition:
	$a0
}