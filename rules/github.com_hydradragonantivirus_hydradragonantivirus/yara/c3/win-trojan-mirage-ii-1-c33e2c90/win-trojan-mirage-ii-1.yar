rule Win_Trojan_Mirage_II_1
{
strings:
	$a0 = { 01e89b00b440badd01b90b00e8bc00e89700b440ba1802b90b00e8ae0033d2b9cc02b440e8 }


condition:
	$a0
}