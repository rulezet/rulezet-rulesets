rule Win_Trojan_VGEN_732
{
strings:
	$a0 = { 0200b81530cd2181fb15307432b82135cd21891eaa018c06ac01b82835cd21891eae018c06b001b82125ba0e02 }


condition:
	$a0
}