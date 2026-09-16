rule Win_Trojan_Feebs_97
{
strings:
	$a0 = { 3c68746d6c3e3c686561643e3c7469746c653e }

	$a1 = { 66756e6374696f6e20[0-15]297b72657475726e20??7d3b }

	$a2 = { 297b72657475726e20??7d3b }

	$a3 = { 3d756e65736361706528[0-200]6576616c28 }

	$a4 = { 3c2f7363726970743e3c }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}