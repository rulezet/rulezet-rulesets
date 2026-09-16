rule Win_Trojan_V_97
{
strings:
	$a0 = { 8edb56e857005157891fff0e13048b1e1304b106d3e326 }


condition:
	$a0
}