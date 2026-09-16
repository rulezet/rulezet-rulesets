rule Win_Trojan_Chest_2
{
strings:
	$a0 = { 3e3c0cd08070f02e3c0d07f4d002eb1e1dd03c0ed006df01eb0e3c0f750af0e4e711fa31c0 }


condition:
	$a0
}