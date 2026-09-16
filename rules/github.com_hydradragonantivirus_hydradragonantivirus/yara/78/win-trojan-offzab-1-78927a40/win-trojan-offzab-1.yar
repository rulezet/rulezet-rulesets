rule Win_Trojan_Offzab_1
{
strings:
	$a0 = { 4b5950b44abb0001cd210f82b600b88716cd2f0bc00f85ab00893e48018c064a010bf6740c8bde }


condition:
	$a0
}