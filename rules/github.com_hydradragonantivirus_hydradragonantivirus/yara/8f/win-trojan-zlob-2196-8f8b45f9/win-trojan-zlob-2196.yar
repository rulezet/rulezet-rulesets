rule Win_Trojan_Zlob_2196
{
strings:
	$a0 = { 2bffbbe8c22e008d1d887fad00d6f7dad6575389cbf7d05a3adc57ff15fa02420077886870e2bf0181ca2bac4a01f7db }


condition:
	$a0
}