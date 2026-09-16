rule Win_Trojan_Markt_1
{
strings:
	$a0 = { ba4559b801facd16e800005d555d81ed1001c6861b01018bc5051a0150eb00e8d805e8c505eb00 }


condition:
	$a0
}