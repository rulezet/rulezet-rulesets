rule Win_Trojan_Small_4373
{
strings:
	$a0 = { b810000087c1c03250e83e00000069d8 }


condition:
	$a0
}