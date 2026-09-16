rule Win_Trojan_Gysium_1
{
strings:
	$a0 = { 268b1e850a268b0e0b01ba0001cd21b440268b0e0f01268b1e850a268b16880a8edaba0000cd }


condition:
	$a0
}