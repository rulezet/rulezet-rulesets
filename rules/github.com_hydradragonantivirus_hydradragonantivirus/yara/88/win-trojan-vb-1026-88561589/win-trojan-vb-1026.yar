rule Win_Trojan_VB_1026
{
strings:
	$a0 = { 436c69656e74654e6577746f6e }

	$a1 = { 436f6e74726f6c52656d6f746f }

	$a2 = { 5465726d696e617250726f6365736f }

	$a3 = { 2f54726f79616e6f2e657865 }


condition:
	$a0 and $a1 and $a2 and $a3
}