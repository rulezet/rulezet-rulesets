rule Win_Trojan_LibertyBoot_1
{
strings:
	$a0 = { 312833d2cd130dbb5c0653cb2e803ebc06bc060a744633c08e }


condition:
	$a0
}