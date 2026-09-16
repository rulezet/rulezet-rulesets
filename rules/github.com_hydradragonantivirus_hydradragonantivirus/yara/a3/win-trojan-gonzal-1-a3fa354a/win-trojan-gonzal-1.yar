rule Win_Trojan_Gonzal_1
{
strings:
	$a0 = { 35cd21891e3c018c063e01b425ba1901cd21ba4001cd279c80fc4b751b60b8023dcd218bd81e0e1fb440ba0001b9 }


condition:
	$a0
}