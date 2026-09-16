rule Win_Trojan_Vundo_450
{
strings:
	$a0 = { 807c2408010f859a0b000060be00a005108dbe0070faff5789e58d9c2480c1ffff31c05039dc75 }


condition:
	$a0
}