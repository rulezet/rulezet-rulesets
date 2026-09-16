rule Win_Trojan_Warrier_1
{
strings:
	$a0 = { 1e030083c39f891e0300c60600005a }


condition:
	$a0
}