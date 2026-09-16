rule Win_Trojan_Maus_1
{
strings:
	$a0 = { d02ea326012e892624018cc88ed0bcf7011e8ed858a328 }


condition:
	$a0
}