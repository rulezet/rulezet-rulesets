rule Win_Trojan_Tiny_41
{
strings:
	$a0 = { b6fd41cd21b440b601b190cd21b440591f99cd210e1fb801578b0ef8fc8b16fafc80e1e0cd21 }


condition:
	$a0
}