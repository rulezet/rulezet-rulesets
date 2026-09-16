rule Win_Trojan_VGEN_373
{
strings:
	$a0 = { 6800001e0660e800005e81ee0a00b8b0b0cd213dbaba7502eb65b462cd2193488ed8803e00005a7402eb50832e0300 }


condition:
	$a0
}