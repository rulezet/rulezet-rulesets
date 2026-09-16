rule Win_Trojan_Pariah_1
{
strings:
	$a0 = { 03cd21813e1703454e751281061c031e03b440b91e03ba0000cd21eb03e8630032c0e86900b4 }


condition:
	$a0
}