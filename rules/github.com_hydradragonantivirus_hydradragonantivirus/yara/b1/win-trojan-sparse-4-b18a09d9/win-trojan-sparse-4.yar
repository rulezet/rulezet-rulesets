rule Win_Trojan_Sparse_4
{
strings:
	$a0 = { 0fcd2150b43db002cd2189c3b442b9 }


condition:
	$a0
}