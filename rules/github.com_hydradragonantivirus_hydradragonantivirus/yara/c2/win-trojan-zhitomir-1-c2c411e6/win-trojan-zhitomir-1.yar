rule Win_Trojan_Zhitomir_1
{
strings:
	$a0 = { 8b1eb505cd21c3b43f8b1eb505cd21c3b4408b1eb505cd21c3b90400d1e2d1e083d200e2f7 }


condition:
	$a0
}