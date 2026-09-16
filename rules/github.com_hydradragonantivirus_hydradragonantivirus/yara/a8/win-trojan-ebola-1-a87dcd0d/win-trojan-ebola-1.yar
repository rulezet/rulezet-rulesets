rule Win_Trojan_Ebola_1
{
strings:
	$a0 = { 351109269b0ec5477c7a7f807e57cc9b2e57b23f3c2db50157cc3a2d3748e12a6b11e1269b51b23f }


condition:
	$a0
}