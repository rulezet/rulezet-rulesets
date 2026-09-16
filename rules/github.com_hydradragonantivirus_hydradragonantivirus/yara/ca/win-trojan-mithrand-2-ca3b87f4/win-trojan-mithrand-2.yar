rule Win_Trojan_Mithrand_2
{
strings:
	$a0 = { 0189fe83eef0ff06fc02b9f001f3a48cc08ed8babd02 }


condition:
	$a0
}