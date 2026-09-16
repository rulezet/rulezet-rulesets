rule Win_Trojan_Small_4274
{
strings:
	$a0 = { e8??0000006a01[0-255]5860505b[0-8]31c9 }


condition:
	$a0
}