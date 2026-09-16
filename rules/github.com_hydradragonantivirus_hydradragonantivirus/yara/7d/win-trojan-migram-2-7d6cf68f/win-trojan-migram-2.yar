rule Win_Trojan_Migram_2
{
strings:
	$a0 = { 02cd13b405b500b101b600b202cd13 }


condition:
	$a0
}