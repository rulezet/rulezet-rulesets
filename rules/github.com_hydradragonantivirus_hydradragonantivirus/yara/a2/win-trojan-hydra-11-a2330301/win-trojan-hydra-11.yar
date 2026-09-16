rule Win_Trojan_Hydra_11
{
strings:
	$a0 = { b8003fb9ffffba5701cd210557012ea3 }


condition:
	$a0
}