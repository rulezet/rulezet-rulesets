rule Win_Trojan_Agiplan_1
{
strings:
	$a0 = { 25cd21b82135cd21891ee4058c06e6 }


condition:
	$a0
}