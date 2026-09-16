rule Win_Trojan_UU_1
{
strings:
	$a0 = { 3c6f6d75ef807c023a75e9be0001e81a00b8024233c933d2cd21b4408b0e7e02ba8702cd21b43e }


condition:
	$a0
}