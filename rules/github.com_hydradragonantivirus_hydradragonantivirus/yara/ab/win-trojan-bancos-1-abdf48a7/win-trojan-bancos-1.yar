rule Win_Trojan_Bancos_1
{
strings:
	$a0 = { 9ad896d52c8614285a2c5ac74af5505f42301f14bd4e21f05b63f3f586830fcfe12f6b4df79a62057683f6853f73100d5a13bd9f8bfd2288e097655f5ac1dd07 }


condition:
	$a0
}