rule Win_Trojan_Mantis_4
{
strings:
	$a0 = { 160301cd21b405b200b600b55ab101b008cd13b400cd21 }


condition:
	$a0
}