rule Win_Trojan_Candyman_3
{
strings:
	$a0 = { 010300550000000000ffff00000000376c0000080000000903 }


condition:
	$a0
}