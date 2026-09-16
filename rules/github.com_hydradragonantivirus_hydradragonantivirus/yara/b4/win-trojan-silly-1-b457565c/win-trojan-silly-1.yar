rule Win_Trojan_Silly_1
{
strings:
	$a0 = { e800005d81ed03012ec686????008d96????b44ee80e00 }

	$a1 = { c3b90700b44ecd2172f6b8023d }


condition:
	$a0 and $a1
}