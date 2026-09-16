rule Win_Trojan_USTC_2
{
strings:
	$a0 = { 01002ec746005300b4408b1e4b000e1f33d2b99703cd21595a51528bc28bd1b91000f7f1be2300 }


condition:
	$a0
}