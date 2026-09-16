rule Win_Trojan_Revenge_1
{
strings:
	$a0 = { 0400bac7078b1ea707e8bdfdb002e84802b440b9c8008b1ea707bacf06e8a9fd }


condition:
	$a0
}