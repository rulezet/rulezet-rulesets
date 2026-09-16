rule Win_Trojan_V_77
{
strings:
	$a0 = { 0c00560e1f8a84270081c62800b96f02300446e2fbeb }


condition:
	$a0
}