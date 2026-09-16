rule Win_Trojan_Demon3b_5
{
strings:
	$a0 = { 1480f23850535152fa83c408fb2e8814b401cd1646b419cd2181fe131875df }


condition:
	$a0
}