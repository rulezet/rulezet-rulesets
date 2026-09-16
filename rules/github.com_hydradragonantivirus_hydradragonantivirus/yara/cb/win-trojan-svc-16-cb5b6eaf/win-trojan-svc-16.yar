rule Win_Trojan_SVC_16
{
strings:
	$a0 = { e3fb065633d2b484cd215e5681fa9019750a2e3abc }


condition:
	$a0
}