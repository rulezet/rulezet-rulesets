rule Win_Trojan_Mimic_2
{
strings:
	$a0 = { 7f05bd25012e8176003a0945454a75f5 }


condition:
	$a0
}