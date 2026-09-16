rule Win_Trojan_Sector_1
{
strings:
	$a0 = { b203b600b500b102b006cd13b403b200b600b500b102b006cd13cd20 }


condition:
	$a0
}