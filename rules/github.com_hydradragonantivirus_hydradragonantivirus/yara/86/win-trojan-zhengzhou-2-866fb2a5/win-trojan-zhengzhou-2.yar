rule Win_Trojan_ZhengZhou_2
{
strings:
	$a0 = { 0e2b0e7d06ba00018b1e5c01b4409c2eff1e5e019ce887009d7306eb4d }


condition:
	$a0
}