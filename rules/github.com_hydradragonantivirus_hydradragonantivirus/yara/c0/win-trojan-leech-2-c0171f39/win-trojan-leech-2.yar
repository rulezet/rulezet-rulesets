rule Win_Trojan_Leech_2
{
strings:
	$a0 = { 1e0789e58be681c4ed038cd18cc88ed05b4c4c81c62300905830f8504c39f473f78cc0488ed881060300fdff8b1e }


condition:
	$a0
}