rule Win_Trojan_Bublik_5
{
strings:
	$a0 = { e88afdfeffe87721ffff6a486853e74000689c000000c7051ca4420013a74100c70578a342 }


condition:
	$a0
}