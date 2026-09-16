rule Win_Trojan_Comp_2
{
strings:
	$a0 = { cd218ac5983d10007d44bcd9058bdc83c30fb104d3ebb44acd21bfd802be0d00b90c00f3a4ba03008b0e2700b44e }


condition:
	$a0
}