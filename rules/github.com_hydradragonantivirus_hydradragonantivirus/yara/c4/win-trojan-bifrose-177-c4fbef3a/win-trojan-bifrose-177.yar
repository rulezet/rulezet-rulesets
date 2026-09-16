rule Win_Trojan_Bifrose_177
{
strings:
	$a0 = { f33e6726fe17be0040447232e7a948627b012bce79ed6f42ccfc1e0066f829bf019e0c8b00ab78bb3816be4fb80054e5d1aec3a301524f9cf09c4c000ac02d0df0d6b0e0 }


condition:
	$a0
}