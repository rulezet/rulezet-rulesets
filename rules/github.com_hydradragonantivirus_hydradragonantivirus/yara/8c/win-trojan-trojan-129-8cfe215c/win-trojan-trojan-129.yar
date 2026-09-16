rule Win_Trojan_Trojan_129
{
strings:
	$a0 = { ba0001b94909cd21b457b0015a59cd21b43ecd218b1e }


condition:
	$a0
}