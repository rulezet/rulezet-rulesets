rule Win_Trojan_Brenda_1
{
strings:
	$a0 = { b44ecd21720fba9e00b8023d }


condition:
	$a0
}