rule Win_Trojan_SVC_14
{
strings:
	$a0 = { 8be3fb065633d2b404cd215e5681fa9019750a2e3abc }


condition:
	$a0
}