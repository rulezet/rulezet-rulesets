rule Win_Trojan_N_42
{
strings:
	$a0 = { 5f2bdb8ed3bc007c8ec4ba0001b90d4ffec72ae4cd13b80602cd1372f5ea0e02007c }


condition:
	$a0
}