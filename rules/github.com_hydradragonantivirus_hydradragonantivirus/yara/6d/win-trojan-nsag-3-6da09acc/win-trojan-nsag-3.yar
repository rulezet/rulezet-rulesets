rule Win_Trojan_Nsag_3
{
strings:
	$a0 = { 3b0000004f4c4541444d }

	$a1 = { 58837c2408016075098bd88d40 }


condition:
	$a0 and $a1
}