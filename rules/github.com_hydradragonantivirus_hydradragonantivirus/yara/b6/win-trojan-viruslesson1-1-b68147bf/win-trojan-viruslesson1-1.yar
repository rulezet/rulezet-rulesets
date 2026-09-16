rule Win_Trojan_Viruslesson1_1
{
strings:
	$a0 = { 4d909090e800005e81c6c200bf0001fca5a581eec900b44ebabf0003 }


condition:
	$a0
}