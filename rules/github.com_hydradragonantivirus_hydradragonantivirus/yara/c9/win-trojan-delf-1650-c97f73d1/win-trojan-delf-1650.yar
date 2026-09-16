rule Win_Trojan_Delf_1650
{
strings:
	$a0 = { 01a1745a41008b08ff51fca120444100bac43e4100e8ba0bffffe841f6feffe848ecfeffe8a7faffffe9ea010000b8f43e4100e8843affff84c0755ae8f7f8ffff }


condition:
	$a0
}