rule Win_Trojan_Truko_2
{
strings:
	$a0 = { 3245f4ffebde5f5e5b8be55dc300ffffffff0c0000007475726b6f6a616e2e696e6900000000ffffffff060000004d6574696e320000ffffffff04000000436861 }


condition:
	$a0
}