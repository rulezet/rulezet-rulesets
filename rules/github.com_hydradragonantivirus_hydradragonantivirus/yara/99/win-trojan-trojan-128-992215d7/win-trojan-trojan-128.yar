rule Win_Trojan_Trojan_128
{
strings:
	$a0 = { 40ba0001b9ee09cd21b457b0015a59cd21b43ecd218b1e }


condition:
	$a0
}