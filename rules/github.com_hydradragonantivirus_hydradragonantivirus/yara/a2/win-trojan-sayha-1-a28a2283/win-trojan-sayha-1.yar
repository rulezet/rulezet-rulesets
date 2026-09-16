rule Win_Trojan_Sayha_1
{
strings:
	$a0 = { e800005e83c6138a0733c62e32048807fb81fb720277e1e4a401a8a86f1f19885828127cb663d464 }


condition:
	$a0
}