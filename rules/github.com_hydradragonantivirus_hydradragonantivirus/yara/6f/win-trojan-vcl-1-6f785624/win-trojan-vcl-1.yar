rule Win_Trojan_VCL_1
{
strings:
	$a0 = { e800005d9081ed0601e8 }

	$a1 = { 8db60f01b995018134????4646e2f8c3 }


condition:
	$a0 and $a1
}