rule Win_Trojan_Agent_32071
{
strings:
	$a0 = { 5589e5e987f6ffffff45fc395dfc0f82bcf7ffffff25c2366715ff35fa3a67155850ff2559386715 }


condition:
	$a0
}