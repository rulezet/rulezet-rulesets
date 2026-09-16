rule Win_Trojan_Peed_58
{
strings:
	$a0 = { 68bdcaffff4889c583ed0283ed036609edf37405050002000089ea09eaf375e8 }


condition:
	$a0
}