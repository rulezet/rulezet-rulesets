rule Win_Trojan_Deicide_14
{
strings:
	$a0 = { ba0001b94a09cd21b457b0015a59cd21b43ecd218b1e }


condition:
	$a0
}