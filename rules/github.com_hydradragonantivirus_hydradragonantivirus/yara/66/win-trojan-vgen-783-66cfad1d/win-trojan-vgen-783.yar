rule Win_Trojan_VGEN_783
{
strings:
	$a0 = { e800005d81ed4b010e1f0e078db6f301bf0001a5a5a4b41a8d96fd01cd21c686ec0100b44e8d96ed01b9000080beec01 }


condition:
	$a0
}