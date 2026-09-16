rule Win_Trojan_PS_49
{
strings:
	$a0 = { bb7d01bf16012e81352f0f47474b75f6 }


condition:
	$a0
}