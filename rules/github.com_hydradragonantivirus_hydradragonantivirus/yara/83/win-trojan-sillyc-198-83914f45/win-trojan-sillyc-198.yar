rule Win_Trojan_SillyC_198
{
strings:
	$a0 = { 3533c9cd21b43fb93600b905008d96af0290cd2180beb202500f849c0081beaf024d5a0f849200b8024233d2eb }


condition:
	$a0
}