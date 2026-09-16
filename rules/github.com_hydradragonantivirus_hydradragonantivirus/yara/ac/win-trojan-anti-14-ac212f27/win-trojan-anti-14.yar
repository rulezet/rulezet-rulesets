rule Win_Trojan_Anti_14
{
strings:
	$a0 = { c08ec0cd130e1f803e0b00007424beae0183c610803c8075f8 }


condition:
	$a0
}