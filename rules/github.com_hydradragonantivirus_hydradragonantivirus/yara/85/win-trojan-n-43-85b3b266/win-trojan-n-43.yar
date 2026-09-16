rule Win_Trojan_N_43
{
strings:
	$a0 = { e800005f2bdb8ed3bc007c8ec4ba0001b9034ffec72ae4cd13b80702cd1372f5ea9102007c }


condition:
	$a0
}