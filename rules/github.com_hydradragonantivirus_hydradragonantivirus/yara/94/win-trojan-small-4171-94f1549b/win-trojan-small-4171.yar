rule Win_Trojan_Small_4171
{
strings:
	$a0 = { cd2acd2a83c8ff40e800000000 }


condition:
	$a0
}