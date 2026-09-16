rule Win_Trojan_Topo_1
{
strings:
	$a0 = { 2e32263d002e88244681fe490375ee }


condition:
	$a0
}