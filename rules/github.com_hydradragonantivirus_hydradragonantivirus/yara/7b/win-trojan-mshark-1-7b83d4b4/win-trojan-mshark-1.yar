rule Win_Trojan_Mshark_1
{
strings:
	$a0 = { d6cd2132db5681c65601b91400ac341302d8e2f95e38 }


condition:
	$a0
}