rule Win_Trojan_Diskjeb_2
{
strings:
	$a0 = { 8cc02e01060e012eff2e0c010000 }


condition:
	$a0
}