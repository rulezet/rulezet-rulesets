rule Win_Trojan_Estonia_1
{
strings:
	$a0 = { 518bca8bfb03fa8bf7ac2807ad2ae08ac4aa46e2f759e2 }


condition:
	$a0
}