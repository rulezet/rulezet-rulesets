rule Win_Trojan_VGEN_369
{
strings:
	$a0 = { 4157cd213d5052744cb44abbffffcd2183eb0cb44acd21b448bb0b00cd217235488ec026c7060100080050b82135cd }


condition:
	$a0
}