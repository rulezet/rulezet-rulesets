rule Win_Trojan_QFat_9
{
strings:
	$a0 = { b90001ba00008edebb0001cd26ebef003bd3731af7f38bd8e461a80375080c03e661b0b6e643 }


condition:
	$a0
}