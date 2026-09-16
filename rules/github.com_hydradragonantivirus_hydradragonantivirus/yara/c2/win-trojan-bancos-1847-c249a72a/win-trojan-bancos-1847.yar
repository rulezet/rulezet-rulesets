rule Win_Trojan_Bancos_1847
{
strings:
	$a0 = { 81c809e3080aa68cc87308b98a346dbbcbe4ba28d84cdf2226ae08cd6eb505e08ea4ee8c1595e73585a1d65d0b2e124a579e0444b42ccacbb50976d2be2c109ef4e20b7ca989 }


condition:
	$a0
}