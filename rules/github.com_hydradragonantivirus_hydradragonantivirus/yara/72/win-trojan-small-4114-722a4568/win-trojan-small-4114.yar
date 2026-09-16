rule Win_Trojan_Small_4114
{
strings:
	$a0 = { e82c000000cd03e82a000000c2300031c08b52 }


condition:
	$a0
}