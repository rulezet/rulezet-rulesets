rule Win_Trojan_WestUkrain_1
{
strings:
	$a0 = { 902a2e434f4d002000035765737465726e20556b7261696e658b2e010183c503b41aba120203d5cd21 }


condition:
	$a0
}