rule Win_Trojan_Breaker_1
{
strings:
	$a0 = { 1075f538bfc2037504888fc203b3408a87bd038887bd014b75f5b80103cd1331c08ed8a3897c }


condition:
	$a0
}