rule Win_Trojan_Miny_1
{
strings:
	$a0 = { e8fd77232d0300a30001c606020143b440b9000133d2cd21b000e89000b440baff00b90400cd21 }


condition:
	$a0
}