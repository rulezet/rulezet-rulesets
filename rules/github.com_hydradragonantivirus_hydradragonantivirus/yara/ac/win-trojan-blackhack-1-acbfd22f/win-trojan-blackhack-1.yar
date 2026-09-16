rule Win_Trojan_BlackHack_1
{
strings:
	$a0 = { be1204468b042d05008904b106d3e0a32d7c8ec0b94200be007c33fffcf3a4ea3a000000b80102 }


condition:
	$a0
}