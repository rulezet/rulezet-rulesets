rule Win_Trojan_B_109
{
strings:
	$a0 = { b82a0250b805028b0e307c418b16327c }


condition:
	$a0
}