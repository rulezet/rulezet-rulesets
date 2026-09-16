rule Win_Trojan_N_36
{
strings:
	$a0 = { abcd13eb0490e9b10081fbcdab7502ebf55351525657 }


condition:
	$a0
}