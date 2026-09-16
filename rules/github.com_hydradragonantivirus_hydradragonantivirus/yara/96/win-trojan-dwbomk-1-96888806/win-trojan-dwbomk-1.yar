rule Win_Trojan_Dwbomk_1
{
strings:
	$a0 = { 8b1e0b01b95f02ba0001cd21b442b0008b1e0b01b900 }


condition:
	$a0
}