rule Win_Trojan_Tack_3
{
strings:
	$a0 = { 408b1e4f02ba5702b90600cd21b800428b1e4f025a33c9cd21b4408b1e4f02ba0001b9dd01cd21 }


condition:
	$a0
}