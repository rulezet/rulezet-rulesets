rule Win_Trojan_EM250_1
{
strings:
	$a0 = { ad0257ebea72419c1ee88bff753881bf0001454d7530d167088bfb8bf381c6f60183c714a5a58b }


condition:
	$a0
}