rule Win_Trojan_Ramdile_1
{
strings:
	$a0 = { e8000000005d81ed141040008dbd30104000b950290000f61747e2fbe92c290000 }


condition:
	$a0
}