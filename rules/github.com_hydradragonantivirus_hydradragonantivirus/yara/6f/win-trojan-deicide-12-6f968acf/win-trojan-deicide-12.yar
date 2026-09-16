rule Win_Trojan_Deicide_12
{
strings:
	$a0 = { 40ba0001b95202cd21b457b0015a59cd21b43ecd218b1e }


condition:
	$a0
}