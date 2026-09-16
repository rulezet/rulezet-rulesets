rule Win_Trojan_Agent_36770
{
strings:
	$a0 = { 807c2408010f85940b000060be00d043008dbe0040fcff5789e58d9c2480c1ffff31c05039dc75fb4646536869e105 }


condition:
	$a0
}