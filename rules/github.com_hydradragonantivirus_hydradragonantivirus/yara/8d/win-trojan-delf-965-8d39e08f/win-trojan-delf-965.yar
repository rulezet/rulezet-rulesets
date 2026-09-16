rule Win_Trojan_Delf_965
{
strings:
	$a0 = { a154ad4700ba88604700e8a0ebf8ff75338d45f8ba64ad4700b900010000e8f8e9f8ff8d45f8baac604700e843eaf8ff8b45f8e83f2ff9ff84c074088b45fce8c7f5ffff }


condition:
	$a0
}